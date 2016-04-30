'use strict';
var util = require('util');
var stream = require('stream');
var crypto = require('crypto');

var BYTE = 255;
var FIN = 128;
var MASK = 128;
var RSV1 = 64;
var RSV2 = 32;
var RSV3 = 16;
var OPCODE = 15;
var LENGTH = 127;

var MODE_TEXT = 1;
var MODE_BINARY = 2;

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

function Rfc6455Protocol() {
  stream.Writable.call(this);
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

Rfc6455Protocol.prototype.buildFrame = function(buffer, opcode, errorCode) {
  errorCode = errorCode || -1;
  var masking = true;
  var insert = (errorCode > 0) ? 2 : 0;
  var length = (!buffer ? 0 : buffer.length) + insert;
  var header = (length <= 125) ? 2 : (length <= 65535 ? 4 : 10);
  var offset = header + (masking ? 4 : 0);
  var masked = masking ? MASK : 0;
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
    wsFrame[2] = (Math.floor(length / Math.pow(2, 56))) & BYTE;
    wsFrame[3] = (Math.floor(length / Math.pow(2, 48))) & BYTE;
    wsFrame[4] = (Math.floor(length / Math.pow(2, 40))) & BYTE;
    wsFrame[5] = (Math.floor(length / Math.pow(2, 32))) & BYTE;
    wsFrame[6] = (Math.floor(length / Math.pow(2, 24))) & BYTE;
    wsFrame[7] = (Math.floor(length / Math.pow(2, 16))) & BYTE;
    wsFrame[8] = (Math.floor(length / Math.pow(2, 8)))  & BYTE;
    wsFrame[9] = length & BYTE;
  }
  if(errorCode > 0) {
    wsFrame[offset] = (Math.floor(errorCode / 256)) & BYTE;
    wsFrame[offset+1] = errorCode & BYTE;
  }
  if(buffer) {
    buffer.copy(wsFrame, offset + insert, 0, buffer.length);
  }
  if(masking) {
    var mask = crypto.randomBytes(4);
    mask.copy(wsFrame, header, 0, 4);
    applyMask(wsFrame, mask, offset);
  }
  return wsFrame;
};

Rfc6455Protocol.prototype._write = function(buffer, encoding, cb) {
  var rsv1 = (buffer[0] & RSV1) === RSV1;
  var rsv2 = (buffer[0] & RSV2) === RSV2;
  var rsv3 = (buffer[0] & RSV3) === RSV3;

  if(rsv1 || rsv2 || rsv3) {
    return cb(new Error('RSV not zero'));
  }

  var isFinal = (buffer[0] & FIN) === FIN;
  var opcode = buffer[0] & OPCODE;
  var isMasked = (buffer[1] & MASK) === MASK;

  if(OPCODES[opcode] !== 1) {
    return cb(new Error('Bad opcode'));
  }

  if(FRAGMENTED_OPCODES[opcode] !== 1 && !isFinal) {
    return cb(new Error('Expected non-final packet'));
  }

  var payloadOffset = 2;
  var length = buffer[1] & LENGTH;
  if(length === 126) {
    length = buffer.readUInt16BE(2);
    payloadOffset += 2;
  } else if(length === 127) {
    length = buffer.readUInt32BE(6);
    payloadOffset += 8;
  }

  var payload = null;

  if(isMasked) {
    var maskOffset = payloadOffset;
    payloadOffset += 4;
    var mask = buffer.slice(maskOffset, maskOffset+4);
    payload = applyMask(buffer.slice(payloadOffset), mask);
  } else {
    payload = buffer.slice(payloadOffset);
  }

  cb();
};

module.exports = Rfc6455Protocol;
