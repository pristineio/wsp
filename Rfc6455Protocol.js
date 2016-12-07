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

function Rfc6455Protocol(isMasking, listener) {
  this.listener = listener || function() {};
  this.isMasking = !!isMasking;
  stream.Writable.call(this);
  initialize(this);
}

util.inherits(Rfc6455Protocol, stream.Writable);

var OPCODE_NAMES = new Array(11).fill('undefined');
Object.keys(OPCODES).forEach(function(opCodeName) {
  OPCODE_NAMES[OPCODES[opCodeName]] = opCodeName.toLowerCase();
  var niceName = opCodeName.substring(0,1).toUpperCase() +
    opCodeName.substring(1).toLowerCase();
  Rfc6455Protocol.prototype['build' + niceName + 'Frame'] = function(buffer) {
    return buildFrame(this, buffer, OPCODES[opCodeName]);
  };
});

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

function initialize(self) {
  self.bytesCopied = 0;
  self.state = 0;
  self.header = null;
  self.payload = null;
  self.headerBuffer = Buffer.alloc(0);
}

function buildFrame(self, buffer, opcode) {
  buffer = buffer || Buffer.alloc(0);
  var length = buffer.length;
  var header = (length <= 125) ? 2 : (length <= 65535 ? 4 : 10);
  var offset = header + (self.isMasking ? 4 : 0);
  var masked = self.isMasking ? MASK : 0;
  var wsFrame = Buffer.alloc(length + offset);
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
    wsFrame[2] = Math.floor(length / 2<<55) & BYTE;
    wsFrame[3] = Math.floor(length / 2<<47) & BYTE;
    wsFrame[4] = Math.floor(length / 2<<39) & BYTE;
    wsFrame[5] = Math.floor(length / 2<<31) & BYTE;
    wsFrame[6] = Math.floor(length / 2<<23) & BYTE;
    wsFrame[7] = Math.floor(length / 2<<15) & BYTE;
    wsFrame[8] = Math.floor(length / 2<<7) & BYTE;
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

function emitFrame(self) {
  if(self.header.isMasked) {
    applyMask(self.payload, self.header.mask);
  }
  self.listener(self.header.opcode, self.payload);
  initialize(self);
}

function extractMask(self) {
  if(!self.header.isMasked) {
    return;
  }
  self.header.payloadOffset += 4;
  self.header.mask = Buffer.alloc(4);
  self.headerBuffer.slice(self.header.payloadOffset-4,
    self.header.payloadOffset).copy(self.header.mask);
}

function setPayloadLength(self) {
  if(self.header.payloadLength === 0) {
    emitFrame(self);
    return 0;
  }
  if(self.header.payloadLength === 126) {
    self.header.payloadOffset = 4;
    self.header.payloadLength = self.headerBuffer.readUInt16BE(2);
  } else if(self.header.payloadLength === 127) {
    self.header.payloadOffset = 10;
    self.header.payloadLength = self.headerBuffer.readDoubleBE(2);
    if(self.header.payloadLength >= Number.MAX_SAFE_INTEGER) {
      return new Error('Unsupported UInt64 length');
    }
  }
}

function extractPayload(self, offset, j) {
  self.payload = Buffer.alloc(self.header.payloadLength);
  if(self.header.payloadLength <= self.headerBuffer.length) {
    j = self.header.payloadLength + self.header.payloadOffset + offset;
    self.headerBuffer.slice(self.header.payloadOffset, j)
      .copy(self.payload);
    self.bytesCopied += self.header.payloadLength;
    emitFrame(self);
    return j;
  }
  if(self.header.payloadOffset < self.headerBuffer.length) {
    self.headerBuffer.slice(self.header.payloadOffset).copy(self.payload);
    self.bytesCopied += self.headerBuffer.length -
      self.header.payloadOffset;
  }
}

function extractHeader(self, chunk, offset, j) {
  var temp = Buffer.alloc(self.headerBuffer.length + chunk.length);
  self.headerBuffer.copy(temp);
  chunk.copy(temp, self.headerBuffer.length);
  self.headerBuffer = temp;
  if(self.headerBuffer.length < 14) {
    return 0;
  }
  self.header = {
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
  self.header.reservedBitsZero = (chunk[0] & RSV) === 0;
  self.header.isFinal = (chunk[0] & FIN) === FIN;
  self.header.opcode = chunk[0] & OPCODE;
  self.header.validOpcode = VALID_OPCODES[self.header.opcode] === 1;
  self.header.isContinuation = self.header.opcode === 0;
  self.header.isMasked = (chunk[1] & MASK) === MASK;
  self.header.payloadLength = chunk[1] & LENGTH;
  self.header.payloadOffset = 2;
  if(!self.header.reservedBitsZero) {
    self.emit('error', new Error('RSV not zero'));
    return 0;
  }
  if(!self.header.validOpcode) {
    self.emit('error', new Error('Invalid opcode'));
    return 0;
  }
  if(FRAGMENTED_OPCODES[self.header.opcode] !== 1 && !self.header.isFinal) {
    self.emit('error', new Error('Expected non-final packet'));
    return 0;
  }
  var result = setPayloadLength(self);
  if(result instanceof Error) {
    self.emit('error', result);
    return 0;
  }
  extractMask(self);
  extractPayload(self, offset, j);
  self.state = 1;
}

function extractFrame(self, chunk_, offset) {
  var j = 0;
  var chunk = chunk_.slice(offset);
  if(chunk.length === 0) {
    return j;
  }
  switch(self.state) {
    case 0:
      extractHeader(self, chunk, offset, j);
      break;
    case 1:
      j = Math.min(chunk.length, self.header.payloadLength - self.bytesCopied);
      chunk.copy(self.payload, self.bytesCopied, 0, j);
      self.bytesCopied += j;
      if(self.bytesCopied === self.header.payloadLength) {
        emitFrame(self);
        return j;
      }
      break;
  }
  return j;
}

Rfc6455Protocol.prototype._write = function(chunk, encoding, cb) {
  var self = this;
  var offset = 0;
  do {
    offset = extractFrame(self, chunk, offset);
  } while(offset > 0);
  cb();
};

Rfc6455Protocol.prototype.OPCODES = OPCODES;
Rfc6455Protocol.prototype.OPCODE_NAMES = OPCODE_NAMES;

module.exports = Rfc6455Protocol;
