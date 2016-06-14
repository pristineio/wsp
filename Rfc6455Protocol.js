'use strict';
var util = require('util');
var stream = require('stream');
var crypto = require('crypto');

var OPCODES = {
  CONTINUATION: 0,
  TEXT: 1,
  BINARY: 2,
  CLOSE: 8,
  PING: 9,
  PONG: 10
};

var VALID_OPCODES = new Array(11).fill(0);
VALID_OPCODES[0] = 1;
VALID_OPCODES[1] = 1;
VALID_OPCODES[2] = 1;
VALID_OPCODES[8] = 1;
VALID_OPCODES[9] = 1;
VALID_OPCODES[10] = 1;

var FRAGMENTED_OPCODES = new Array(11).fill(0);
FRAGMENTED_OPCODES[0] = 1;
FRAGMENTED_OPCODES[1] = 1;
FRAGMENTED_OPCODES[2] = 1;

var FIN = 128;
var RSV = 112;
var BYTE = 255;
var MASK = 128;
var OPCODE = 15;
var LENGTH = 127;

function initialize(self) {
  self.bytesCopied = 0;
  self.state = 0;
  self.header = null;
  self.payload = null;
}

function applyMask(payload, mask, offset) {
  if(!mask || mask.length === 0 || !payload) {
    return;
  }
  offset = offset || 0;
  var i = -1;
  var l = payload.length-offset;
  while(++i < l) {
    var x = offset+i;
    payload[x] = payload[x] ^ mask[i%4];
  }
}

function Rfc6455Protocol(isMasking) {
  this.isMasking = !!isMasking;
  stream.Writable.call(this);
  initialize(this);
}

util.inherits(Rfc6455Protocol, stream.Writable);

var OPCODES_NAMES = new Array(11).fill('undefined');
Object.keys(OPCODES).forEach(function(opCodeName) {
  OPCODES_NAMES[OPCODES[opCodeName]] = opCodeName.toLowerCase();
  var niceName = opCodeName.substring(0,1).toUpperCase() +
    opCodeName.substring(1).toLowerCase();
  Rfc6455Protocol.prototype['build' + niceName + 'Frame'] = function(buffer) {
    return buildFrame(this, buffer, OPCODES[opCodeName]);
  };
});

function emitFrame(self) {
  if(self.header.isMasked) {
    applyMask(self.payload, self.header.mask);
  }
  switch(self.header.opcode) {
    case OPCODES.CLOSE:
    case OPCODES.PING:
    case OPCODES.TEXT:
      self.emit(OPCODES_NAMES[self.header.opcode], self.payload);
      break;
  }
}

function buildFrame(self, buffer, opcode) {
  buffer = buffer || new Buffer(0).fill(0);
  var length = buffer.length;
  var header = (length <= 125) ? 2 : (length <= 65535 ? 4 : 10);
  var offset = header + (self.isMasking ? 4 : 0);
  var masked = self.isMasking ? MASK : 0;
  var wsFrame = new Buffer(length + offset);
  wsFrame.fill(0);
  wsFrame[0] = FIN | opcode;
  if(length <= 125) {
    wsFrame[1] = masked | length;
  } else if(length <= 65535) {
    wsFrame[1] = masked | 126;
    wsFrame[2] = Math.floor(length / 256);
    wsFrame[3] = length & BYTE;
  } else {
    wsFrame[1] = masked | 127;
    wsFrame[2] = Math.floor(length / Math.pow(2,56)) & BYTE;
    wsFrame[3] = Math.floor(length / Math.pow(2,48)) & BYTE;
    wsFrame[4] = Math.floor(length / Math.pow(2,40)) & BYTE;
    wsFrame[5] = Math.floor(length / Math.pow(2,32)) & BYTE;
    wsFrame[6] = Math.floor(length / Math.pow(2,24)) & BYTE;
    wsFrame[7] = Math.floor(length / Math.pow(2,16)) & BYTE;
    wsFrame[8] = Math.floor(length / Math.pow(2,8)) & BYTE;
    wsFrame[9] = length & BYTE;
  }
  buffer.copy(wsFrame, offset, 0, buffer.length);
  if(self.isMasking) {
    var mask = crypto.randomBytes(4);
    mask.copy(wsFrame, header, 0, 4);
    applyMask(wsFrame, mask, offset);
  }
  return wsFrame;
}

function processHeader(self, chunk_, cb) {
  var header = {
    mask: null,
    validOpcode: false,
    reservedBitsZero: false,
    isContinuation: false,
    isFinal: false,
    isMasked: false,
    opcode: -1,
    payloadOffset: 0,
    payloadLength: 0
  };

  var chunk = chunk_.slice(0);

  header.reservedBitsZero = (chunk[0] & RSV) === 0;
  header.isFinal = (chunk[0] & FIN) === FIN;
  header.opcode = chunk[0] & OPCODE;
  header.validOpcode = VALID_OPCODES[header.opcode] === 1;
  header.isContinuation = header.opcode === 0;
  header.isMasked = (chunk[1] & MASK) === MASK;
  header.payloadLength = chunk[1] & LENGTH;
  header.payloadOffset = 2;

  if(!header.reservedBitsZero) {
    return cb(new Error('RSV not zero'));
  }

  if(!header.validOpcode) {
    return cb(new Error('Unknown opcode'));
  }

  if(FRAGMENTED_OPCODES[header.opcode] !== 1 && !header.isFinal) {
    return cb(new Error('Expected non-final packet'));
  }

  if(header.payloadLength === 126) {
    header.payloadLength = chunk.readUInt16BE(2);
    header.payloadOffset = 4;
  } else if(header.payloadLength === 127) {
    return cb(new Error('Unsupported UInt64 length'));
  }

  if(header.isMasked) {
    header.payloadOffset += 4;
    header.mask = new Buffer(4).fill(0);
    chunk.slice(header.payloadOffset-4, header.payloadOffset).copy(header.mask);
  }

  self.header = header;

  if(self.header.payloadLength > 0) {
    self.payload = new Buffer(self.header.payloadLength).fill(0);
    chunk_.slice(self.header.payloadOffset).copy(self.payload);
    self.bytesCopied += (chunk_.length - self.header.payloadOffset);
  }

  if(self.bytesCopied < self.header.payloadLength) {
    self.state = 1;
  } else {
    emitFrame(self);
  }
}

function processPayload(self, chunk_, cb) {
  var innerProcessPayload = function(chunk, amount) {
    amount = amount || chunk.length;
    try {
      chunk.copy(self.payload, self.bytesCopied, 0, amount);
    } catch(_) {
      throw new Error(JSON.stringify({
        bytesCopied: self.bytesCopied,

        chunk_: chunk,
        'chunk_.length': chunk.length,

        payload: self.payload,
        'payload.length': self.header.payloadLength,

        i: 0,
        j: amount
      }));
    }
    self.bytesCopied += amount;
    if(self.bytesCopied === self.header.payloadLength) {
      emitFrame(self);
      initialize(self);
    }
  };

  var remaining = self.bytesCopied + chunk_.length - self.header.payloadLength;

  var amount = remaining > 0 ?
    self.header.payloadLength - self.bytesCopied :
    chunk_.length;

  if(amount < 0) {
    amount = chunk_.length;
  }

  innerProcessPayload(chunk_, amount);

  if(remaining > 0) {
    var frame = chunk_.slice(amount);
    processHeader(self, frame, cb);
    if(self.state === 1) {
      innerProcessPayload(frame);
    }
  }
}

Rfc6455Protocol.prototype._write = function(chunk, encoding, cb) {
  switch(this.state) {
    case 0: processHeader(this, chunk, cb); break;
    case 1: processPayload(this, chunk, cb); break;
  }
  cb();
};

module.exports = Rfc6455Protocol;
