'use strict';
var util = require('util');
var stream = require('stream');
var crypto = require('crypto');

var payloadBytesWritten;
var payload;
var header;
var state;
var self;

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

var STATES = {
  LISTENING: 0,
  BUFFERING: 1
};

var FIN = 128;
var RSV = 112;
var BYTE = 255;
var MASK = 128;
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

function emitAndReinitialize() {
  if(header.payloadLength === payloadBytesWritten) {
    if(header.isMasked) {
      applyMask(payload, header.mask);
    }
    switch(header.opcode) {
      case OPCODES.TEXT:
      case OPCODES.PING:
      case OPCODES.CLOSE:
        self.emit(OPCODES_NAMES[header.opcode], payload);
        break;
    }
    initialize();
  }
}

function Rfc6455Protocol(isMasking) {
  self = this;
  self.isMasking = !!isMasking;
  stream.Writable.call(this);
  initialize();
}

util.inherits(Rfc6455Protocol, stream.Writable);

var OPCODES_NAMES = new Array(11).fill('undefined');
Object.keys(OPCODES).forEach(function(opCodeName) {
  OPCODES_NAMES[OPCODES[opCodeName]] = opCodeName.toLowerCase();
  var niceName = opCodeName.substring(0,1).toUpperCase() +
    opCodeName.substring(1).toLowerCase();
  Rfc6455Protocol.prototype['build' + niceName + 'Frame'] = function(buffer) {
    return buildFrame(buffer, OPCODES[opCodeName]);
  };
});

function buildFrame(buffer, opcode) {
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

function processHeader(chunk, cb) {
  header.reservedBitsZero = (chunk[0] & RSV) === 0;
  header.isFinal = (chunk[0] & FIN) === FIN;
  header.opcode = chunk[0] & OPCODE;
  header.validOpcode = VALID_OPCODES[header.opcode] === 1;
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

  emitAndReinitialize();

  cb();
}

function processPayload(chunk, cb) {
  chunk.copy(payload, payloadBytesWritten);
  payloadBytesWritten += chunk.length;
  if(payloadBytesWritten > header.payloadLength) {
    return cb(new Error('Payload size'));
  }
  emitAndReinitialize();
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
