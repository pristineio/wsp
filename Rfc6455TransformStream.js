'use strict';
var stream = require('stream');
var crypto = require('crypto');

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

function processHeader(chunk_) {
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
    return new Error('RSV not zero');
  }

  if(!header.validOpcode) {
    return new Error('Unknown opcode');
  }

  if(FRAGMENTED_OPCODES[header.opcode] !== 1 && !header.isFinal) {
    return new Error('Expected non-final packet');
  }

  if(header.payloadLength === 126) {
    header.payloadLength = chunk.readUInt16BE(2);
    header.payloadOffset = 4;
  } else if(header.payloadLength === 127) {
    return new Error('Unsupported UInt64 length');
  }

  if(header.isMasked) {
    header.payloadOffset += 4;
    header.mask = new Buffer(4).fill(0);
    chunk.slice(header.payloadOffset-4, header.payloadOffset).copy(header.mask);
  }

  return header;
}

class Rfc6455TransformStream extends stream.Transform {
  static get OPCODES() {
    return {
      CONTINUATION: 0,
      TEXT: 1,
      BINARY: 2,
      CLOSE: 8,
      PING: 9,
      PONG: 10
    };
  }

  constructor(options) {
    Object.keys(Rfc6455TransformStream.OPCODES).forEach(function(opCodeName) {
      var opcode = Rfc6455TransformStream.OPCODES[opCodeName];
      var niceName = opCodeName.charAt(0).toUpperCase() +
        opCodeName.substring(1).toLowerCase();
      var method = 'build' + niceName + 'Frame';
      Rfc6455TransformStream.prototype[method] = function(buffer) {
        return this.buildFrame(buffer, opcode);
      };
    });

    super({transform: function(chunk, encoding, cb) {
      this.listener = options.listener || function() {};
      this.isMasking = !!options.isMasking;
      this.initialize();
      var offset = 0;
      do { offset = this.extractFrame(chunk, offset); } while(offset > 0);
      if(this.header.isMasked) {
        applyMask(this.payload, this.header.mask);
      }
      this.listener(this.header.opcode, this.payload);
      cb();
    }});
  }

  initialize() {
    this.bytesCopied = 0;
    this.state = 0;
    this.header = null;
    this.payload = null;
  }

  buildFrame(buffer, opcode) {
    buffer = buffer || new Buffer(0).fill(0);
    var length = buffer.length;
    var header = (length <= 125) ? 2 : (length <= 65535 ? 4 : 10);
    var offset = header + (this.isMasking ? 4 : 0);
    var masked = this.isMasking ? MASK : 0;
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
    if(this.isMasking) {
      var mask = crypto.randomBytes(4);
      mask.copy(wsFrame, header, 0, 4);
      applyMask(wsFrame, mask, offset);
    }
    return wsFrame;
  }

  extractFrame(chunk_, offset) {
    if(offset === 0) {
      this.initialize();
    }
    var j = 0;
    var chunk = chunk_.slice(offset);
    if(chunk.length === 0) {
      return j;
    }
    switch(this.state) {
      case 0:
        var result = processHeader(chunk);
        if(result instanceof Error) {
          this.emit('error', result);
          return 0;
        }
        this.header = result;
        if(this.header.payloadLength === 0) {
          return 0;
        }
        this.payload = new Buffer(this.header.payloadLength).fill(0);
        if(this.header.payloadLength <= chunk.length) {
          j = this.header.payloadLength + this.header.payloadOffset + offset;
          chunk.slice(this.header.payloadOffset, j).copy(this.payload);
          this.bytesCopied += this.header.payloadLength;
          return 0;
        }
        chunk.slice(this.header.payloadOffset).copy(this.payload);
        this.bytesCopied += chunk.length - this.header.payloadOffset;
        this.state = 1;
        break;
      case 1:
        j = Math.min(chunk.length, this.header.payloadLength - this.bytesCopied);
        chunk.copy(this.payload, this.bytesCopied, 0, j);
        this.bytesCopied += j;
        if(this.bytesCopied === this.header.payloadLength) {
          return 0;
        }
        break;
    }
    return j;
  }
}

module.exports = Rfc6455TransformStream;
