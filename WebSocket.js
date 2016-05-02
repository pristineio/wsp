'use strict';
var events = require('events');
var crypto = require('crypto');
var util = require('util');
var url = require('url');
var net = require('net');
var Rfc6455Protocol = require('./Rfc6455Protocol');
var self;

var READY_STATES = {
  CONNECTING: 0,
  OPEN: 1,
  CLOSING: 2,
  CLOSED: 3
};

function buildWithSocket(socket, maskFrames) {
  self.socket = socket;
  self.socket.setTimeout(0);
  self.rfc6455Protocol = new Rfc6455Protocol(!!maskFrames);
  self.socket.pipe(self.rfc6455Protocol);

  self.rfc6455Protocol.on('text', function(payload) {
    self.emit('message', payload.toString());
  });

  self.rfc6455Protocol.on('ping', function(payload) {
    self.emit('ping', payload.toString());
  });

  self.rfc6455Protocol.on('close', function(code) {
    self.readyState = READY_STATES.CLOSING;
    self.socket.once('close', function() {
      self.emit('close', code.toString());
      self.readyState = READY_STATES.CLOSED;
    });
  });

  self.rfc6455Protocol.on('error', function(err) {
    self.emit('error', err);
  });

  self.emit('connect');
  self.readyState = READY_STATES.OPEN;
}

function buildWithHandshake(url_, headers, maskFrames) {
  self.readyState = READY_STATES.CLOSED;
  var parsedUrl = url.parse(url_);
  var secret = crypto.randomBytes(16).toString('base64');
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
    buildWithSocket(self.socket, !!maskFrames);
  });
}

function WebSocket(opts) {
  self = this;
  self.readyState = READY_STATES.CLOSED;
  if(!('socket' in opts ^ 'url' in opts)) {
    throw new Error('Specify either URL or socket');
  }
  if(!opts.maskFrames) {
    opts.maskFrames = true;
  } else {
    opts.maskFrames = !!opts.maskFrames;
  }
  if('url' in opts) {
    return buildWithHandshake(opts.url, !opts.headers ? {} : opts.headers,
      opts.maskFrames);
  }
  buildWithSocket(opts.socket, opts.maskFrames);
}

util.inherits(WebSocket, events.EventEmitter);

function buildMethod(fn) {
  return function() {
    if(self.readyState === READY_STATES.CLOSING ||
        self.readyState === READY_STATES.CLOSED) {
      return;
    }
    fn.apply(self, Array.prototype.slice.call(arguments));
  };
}

WebSocket.prototype.send = buildMethod(function(data) {
  self.socket.write(self.rfc6455Protocol.buildTextFrame(new Buffer(data)));
});

WebSocket.prototype.close = buildMethod(function(code) {
  self.readyState = READY_STATES.CLOSING;
  code = code || '1000';
  self.socket.end(self.rfc6455Protocol.buildCloseFrame(new Buffer(code)));
});

WebSocket.prototype.ping = buildMethod(function(data) {
  data = data || 0;
  self.socket.write(self.rfc6455Protocol.buildPingFrame(new Buffer(data)));
});

WebSocket.prototype.READY_STATES = READY_STATES;

module.exports = WebSocket;