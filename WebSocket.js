'use strict';
var events = require('events');
var crypto = require('crypto');
var util = require('util');
var url = require('url');
var net = require('net');
var Rfc6455Protocol = require('./Rfc6455Protocol');

function buildWithSocket(self, maskFrames) {
  self.socket.setNoDelay(true);
  self.socket.setTimeout(0, function() {
    self.readyState = READY_STATES.CLOSED;
    self.emit('close', 'TIMED_OUT');
  });
  self.socket.setKeepAlive(true, 0);

  self.rfc6455Protocol = new Rfc6455Protocol(!!maskFrames,
    function(opcode, payload) {
      payload = payload || '';
      switch(opcode) {
        case Rfc6455Protocol.prototype.OPCODES.CLOSE:
          self.readyState = READY_STATES.CLOSED;
          self.emit('close', payload.toString());
          break;
        case Rfc6455Protocol.prototype.OPCODES.PING:
          self.emit('ping', payload.toString());
          break;
        case Rfc6455Protocol.prototype.OPCODES.PONG:
          self.emit('pong', payload.toString());
          break;
        case Rfc6455Protocol.prototype.OPCODES.TEXT:
          self.emit('message', payload.toString());
          break;
      }
    }
  );

  self.rfc6455Protocol.on('error', function(err) {
    self.emit('error', err);
  });

  self.socket.once('end', function() {
    self.readyState = READY_STATES.CLOSING;
    self.emit('close', '1000');
  });

  self.socket.on('error', function(err) {
    self.emit('error', err);
  });

  self.socket.once('close', function(payload) {
    self.readyState = READY_STATES.CLOSED;
    self.emit('close', '1000');
  });

  self.readyState = READY_STATES.OPEN;
  self.socket.pipe(self.rfc6455Protocol);

  self.emit('connect');
}

function buildWithHandshake(self, url_, headers, maskFrames) {
  self.readyState = READY_STATES.CLOSED;
  var parsedUrl = url.parse(url_);
  var secret = crypto.randomBytes(16).toString('base64');
  if(!parsedUrl.port) {
    parsedUrl.port = parsedUrl.protocol === 'wss:' ? '443' : '80';
  }
  self.socket = net.connect({
    host: parsedUrl.hostname,
    port: parsedUrl.port
  }, function() {
    self.readyState = READY_STATES.CONNECTING;
    var res = [
      'GET ' + parsedUrl.href + ' HTTP/1.1',
      'Upgrade: WebSocket',
      'Connection: Upgrade',
      'Host: ' + parsedUrl.hostname,
      'Origin: ' + parsedUrl.href,
      'Sec-WebSocket-Key: ' + secret,
      'Sec-WebSocket-Version: 13'
    ];
    Object.keys(headers).forEach(function(k) {
      res.push(util.format('%s: %s', k, headers[k]));
    });
    res.push('', '');
    self.socket.write(res.join('\r\n'));
  }).once('data', function(res) {
    res = res.toString();
    res.split(/\r?\n/).forEach(function(line, i) {
      if(i === 0 && !/HTTP\/1\.1 101 Switching Protocols/i.test(line)) {
        self.readyState = READY_STATES.CLOSED;
        throw new Error('Invalid protocol: ' + line);
      }
      if(!/Sec-WebSocket-Accept/i.test(line)) {
        return;
      }
      var headerSecret = line.split(/Sec-WebSocket-Accept: /i)[1];
      var sha1 = crypto.createHash('sha1');
      sha1.update((secret + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'));
      if(sha1.digest('base64').trim() !== headerSecret) {
        self.readyState = READY_STATES.CLOSED;
        throw new Error('Invalid secret');
      }
    });
    buildWithSocket(self, self.socket, !!maskFrames);
  });
}

function WebSocket(opts) {
  var self = this;
  self.readyState = READY_STATES.CLOSED;
  if(!('socket' in opts ^ 'url' in opts)) {
    throw new Error('Specify either URL or socket');
  }
  opts.maskFrames = !!opts.maskFrames;
  if('url' in opts) {
    return buildWithHandshake(self, opts.url, !opts.headers ? {} : opts.headers,
      opts.maskFrames);
  }
  self.socket = opts.socket;
  buildWithSocket(self, opts.maskFrames);
}

util.inherits(WebSocket, events.EventEmitter);

WebSocket.READY_STATES = {
  CONNECTING: 0,
  OPEN: 1,
  CLOSING: 2,
  CLOSED: 3
};

var READY_STATES = WebSocket.READY_STATES;

WebSocket.prototype.send = function(data) {
  var self = this;
  if(self.readyState === READY_STATES.CLOSING ||
      self.readyState === READY_STATES.CLOSED) {
    return;
  }
  self.socket.write(self.rfc6455Protocol.buildTextFrame(Buffer.from(data)));
};

WebSocket.prototype.close = function(code) {
  var self = this;
  if(self.readyState === READY_STATES.CLOSING ||
      self.readyState === READY_STATES.CLOSED) {
    return;
  }
  self.readyState = READY_STATES.CLOSING;
  code = code || '1000';
  try {
    self.socket.end(self.rfc6455Protocol.buildCloseFrame(Buffer.from(code)));
  } catch(ex) {
    self.socket.destroy();
  }
};

WebSocket.prototype.ping = function(data) {
  var self = this;
  if(self.readyState === READY_STATES.CLOSING ||
      self.readyState === READY_STATES.CLOSED) {
    return;
  }
  data = data || 0;
  self.socket.write(self.rfc6455Protocol.buildPingFrame(Buffer.from(data)));
};

WebSocket.prototype.pong = function(data) {
  var self = this;
  if(self.readyState === READY_STATES.CLOSING ||
      self.readyState === READY_STATES.CLOSED) {
    return;
  }
  data = data || 0;
  self.socket.write(self.rfc6455Protocol.buildPongFrame(Buffer.from(data)));
};

WebSocket.prototype.READY_STATES = READY_STATES;

module.exports = WebSocket;
