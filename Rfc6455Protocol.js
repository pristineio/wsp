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

class Rfc6455Protocol extends stream.Transform {
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

  static get OPCODE_NAMES() {
    return {
      0: 'CONTINUATION',
      1: 'TEXT',
      2: 'BINARY',
      8: 'CLOSE',
      9: 'PING',
      10: 'PONG'
    };
  }

  constructor(opts) {
    super({
      transform: function(chunk, encoding, cb) {
        var offset = 0;
        do {
          offset = this.extractFrame(chunk, offset);
        } while(offset > 0);
        cb();
      }
    });
    var self = this;
    this.listener = opts.listener || function() {};
    this.isMasking = !!opts.isMasking;
    this._initialize();
    Object.keys(Rfc6455Protocol.OPCODES).forEach(function(opCodeName) {
      var method = 'build' + opCodeName.substring(0,1).toUpperCase() +
        opCodeName.substring(1).toLowerCase() + 'Frame';
      Rfc6455Protocol.prototype[method] = function(buffer) {
        return self._buildFrame(buffer, Rfc6455Protocol.OPCODES[opCodeName]);
      };
    });
  }

  _applyMask(payload, mask, offset) {
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

  _initialize() {
    this.bytesCopied = 0;
    this.state = 0;
    this.header = null;
    this.payload = null;
    this.headerBuffer = Buffer.alloc(0);
  }

  _buildFrame(buffer, opcode) {
    buffer = buffer || Buffer.alloc(0);
    var length = buffer.length;
    var header = (length <= 125) ? 2 : (length <= 65535 ? 4 : 10);
    var offset = header + (this.isMasking ? 4 : 0);
    var masked = this.isMasking ? MASK : 0;
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
    if(this.isMasking) {
      var mask = crypto.randomBytes(4);
      mask.copy(wsFrame, header, 0, 4);
      this._applyMask(wsFrame, mask, offset);
    }
    return wsFrame;
  }

  emitFrame() {
    if(this.header.isMasked) {
      this._applyMask(this.payload, this.header.mask);
    }
    this.listener(this.header.opcode, this.payload);

    this.push(this.payload);

    this._initialize();
  }

  extractMask() {
    if(!this.header.isMasked) {
      return;
    }
    this.header.payloadOffset += 4;
    if(this.headerBuffer.length < this.header.payloadOffset) {
      return 0;
    }
    this.header.mask = Buffer.alloc(4);
    this.headerBuffer.slice(this.header.payloadOffset-4,
      this.header.payloadOffset).copy(this.header.mask);
  }

  setPayloadLength() {
    if(this.header.payloadLength === 0) {
      this.emitFrame();
      return 0;
    }
    if(this.header.payloadLength === 126) {
      this.header.payloadOffset = 4;
      if(this.headerBuffer.length < this.header.payloadOffset) {
        return 0;
      }
      this.header.payloadLength = this.headerBuffer.readUInt16BE(2);
    } else if(this.header.payloadLength === 127) {
      this.header.payloadOffset = 10;
      if(this.headerBuffer.length < this.header.payloadOffset) {
        return 0;
      }
      this.header.payloadLength = this.headerBuffer.readDoubleBE(2);
      if(this.header.payloadLength >= Number.MAX_SAFE_INTEGER) {
        return new Error('Unsupported UInt64 length');
      }
    }
  }

  extractHeader(chunk, offset, j) {
    var temp = Buffer.alloc(this.headerBuffer.length + chunk.length);
    this.headerBuffer.copy(temp);
    chunk.copy(temp, this.headerBuffer.length);
    this.headerBuffer = temp;
    if(this.headerBuffer.length < 2) {
      return 0;
    }
    this.header = {
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
    this.header.reservedBitsZero = (chunk[0] & RSV) === 0;
    this.header.isFinal = (chunk[0] & FIN) === FIN;
    this.header.opcode = chunk[0] & OPCODE;
    this.header.validOpcode = VALID_OPCODES[this.header.opcode] === 1;
    this.header.isContinuation = this.header.opcode === 0;
    this.header.isMasked = (chunk[1] & MASK) === MASK;
    this.header.payloadLength = chunk[1] & LENGTH;
    this.header.payloadOffset = 2;
    if(!this.header.reservedBitsZero) {
      this.emit('error', new Error('RSV not zero'));
      return 0;
    }
    if(!this.header.validOpcode) {
      this.emit('error', new Error('Invalid opcode'));
      return 0;
    }
    if(FRAGMENTED_OPCODES[this.header.opcode] !== 1 && !this.header.isFinal) {
      this.emit('error', new Error('Expected non-final packet'));
      return 0;
    }
    var result = this.setPayloadLength();
    if(result instanceof Error) {
      this.emit('error', result);
      return 0;
    }
    this.extractMask();
    this.payload = Buffer.alloc(this.header.payloadLength);
    if(this.header.payloadLength <= this.headerBuffer.length) {
      j = this.header.payloadLength + this.header.payloadOffset + offset;
      this.headerBuffer.slice(this.header.payloadOffset, j).copy(this.payload);
      this.bytesCopied += this.header.payloadLength;
      this.emitFrame();
      return;
    }
    if(this.header.payloadOffset < this.headerBuffer.length) {
      this.headerBuffer.slice(this.header.payloadOffset).copy(this.payload);
      this.bytesCopied += this.headerBuffer.length -
        this.header.payloadOffset;
    }
    this.state = 1;
  }

  extractFrame(chunk_, offset) {
    var j = 0;
    var chunk = chunk_.slice(offset);
    if(chunk.length === 0) {
      return j;
    }
    switch(this.state) {
      case 0:
        this.extractHeader(chunk, offset, j);
        break;
      case 1:
        j = Math.min(chunk.length, this.header.payloadLength-this.bytesCopied);
        chunk.copy(this.payload, this.bytesCopied, 0, j);
        this.bytesCopied += j;
        if(this.bytesCopied === this.header.payloadLength) {
          this.emitFrame();
          return j;
        }
        break;
    }
    return j;
  }
}

module.exports = Rfc6455Protocol;
