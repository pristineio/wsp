'use strict';
var util = require('util');
var stream = require('stream');
var crypto = require('crypto');

var self;
var state;
var payloadBytesWritten;
var payload;
var header;

var STATES = {
  LISTENING: 0,
  BUFFERING: 1
};

var BYTE = 255;
var FIN = 128;
var MASK = 128;
var RSV = 112;
var OPCODE = 15;
var LENGTH = 127;

function initialize() {
  state = STATES.LISTENING;
  payloadBytesWritten = 0;
  header = {
    mask: null,
    validOpcode: false,
    reservedBitsZero: false,
    isContinuation: false,
    isFinal: false,
    isMasked: false,
    opcode: -1,
    payloadOffset: 2,
    payloadLength: 0
  };
}

function applyMask(payload, mask, offset) {
  if(mask.length === 0) {
    return payload;
  }
  offset = offset || 0;
  var i = -1;
  var l = payload.length-offset;
  while(++i < l) {
    var x = offset+i;
    payload[x] = payload[x] ^ mask[i%4];
  }
  return payload;
}

function Rfc6455Protocol(isMasking) {
  self = this;
  self.isMasking = !!isMasking;
  stream.Writable.call(this);
  initialize();
}

util.inherits(Rfc6455Protocol, stream.Writable);

Rfc6455Protocol.prototype.opcodes = {
  OP_CONTINUATION: 0,
  OP_TEXT: 1,
  OP_BINARY: 2,
  OP_CLOSE: 8,
  OP_PING: 9,
  OP_PONG: 10
};

var OPCODES = new Array(11).fill(0);
OPCODES[0] = 1;
OPCODES[1] = 1;
OPCODES[2] = 1;
OPCODES[8] = 1;
OPCODES[9] = 1;
OPCODES[10] = 1;

var FRAGMENTED_OPCODES = new Array(11).fill(0);
FRAGMENTED_OPCODES[0] = 1;
FRAGMENTED_OPCODES[1] = 1;
FRAGMENTED_OPCODES[2] = 1;

Rfc6455Protocol.prototype.buildFrame = function(buffer, opcode, err) {
  buffer = buffer || new Buffer(0).fill(0);
  err = err || -1;
  var insert = (err > 0) ? 2 : 0;
  var length = buffer.length + insert;
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
  if(err > 0) {
    wsFrame[offset] = (Math.floor(err / 256)) & BYTE;
    wsFrame[offset+1] = err & BYTE;
  }
  buffer.copy(wsFrame, offset + insert, 0, buffer.length);
  if(self.isMasking) {
    var mask = crypto.randomBytes(4);
    mask.copy(wsFrame, header, 0, 4);
    applyMask(wsFrame, mask, offset);
  }
  return wsFrame;
};

function processHeader(chunk, cb) {
  header.reservedBitsZero = (chunk[0] & RSV) === 0;
  header.isFinal = (chunk[0] & FIN) === FIN;
  header.opcode = chunk[0] & OPCODE;
  header.validOpcode = OPCODES[header.opcode] === 1;
  header.isContinuation = header.opcode === 0;
  header.isMasked = (chunk[1] & MASK) === MASK;
  header.payloadLength = chunk[1] & LENGTH;

  if(!header.reservedBitsZero) {
    return cb(new Error('RSV not zero'));
  }

  if(!header.validOpcode) {
    return cb(new Error('Unknown opcode'));
  }

  if(FRAGMENTED_OPCODES[header.opcode] !== 1 && !header.isFinal) {
    return cb(new Error('Expected non-final packet'));
  }

  state = STATES.BUFFERING;

  if(header.payloadLength === 126) {
    header.payloadLength = chunk.readUInt16BE(2);
    header.payloadOffset += 2;
  } else if(header.payloadLength === 127) {
    // TODO: UInt64 length
    header.payloadLength = chunk.readUInt32BE(6);
    header.payloadOffset += 8;
  }

  payload = new Buffer(header.payloadLength).fill(0);

  if(header.isMasked) {
    header.payloadOffset += 4;
    header.mask = chunk.slice(header.payloadOffset-4, header.payloadOffset);
  }

  chunk.slice(header.payloadOffset, header.payloadLength + header.payloadOffset)
    .copy(payload);

  payloadBytesWritten = chunk.length - header.payloadOffset;

  if(payloadBytesWritten === header.payloadLength) {
    if(header.isMasked) {
      applyMask(payload, header.mask);
    }
    switch(header.opcode) {
      case Rfc6455Protocol.prototype.opcodes.OP_TEXT:
        self.emit('payload', payload);
        break;
      case Rfc6455Protocol.prototype.opcodes.OP_PING:
        self.emit('ping', payload);
        break;
    }
    initialize();
  }

  cb();
}

function processPayload(chunk, cb) {
  chunk.copy(payload, payloadBytesWritten);
  payloadBytesWritten += chunk.length;
  if(payloadBytesWritten > header.payloadLength) {
    return cb(new Error('Payload size'));
  }
  if(header.payloadLength === payloadBytesWritten) {
    if(header.isMasked) {
      applyMask(payload, header.mask);
    }
    switch(header.opcode) {
      case Rfc6455Protocol.prototype.opcodes.OP_TEXT:
        self.emit('payload', payload);
        break;
      case Rfc6455Protocol.prototype.opcodes.OP_PING:
        self.emit('ping', payload);
        break;
    }
    initialize();
  }

  cb();
}


Rfc6455Protocol.prototype._write = function(chunk, encoding, cb) {
  switch(state) {
    case STATES.LISTENING:
      return processHeader(chunk, cb);
    case STATES.BUFFERING:
      return processPayload(chunk, cb);
  }
};

module.exports = Rfc6455Protocol;
