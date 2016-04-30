'use strict';
var events = require('events');
var crypto = require('crypto');
var util = require('util');
var url = require('url');
var net = require('net');
var Rfc6455Protocol = require('./Rfc6455Protocol');
var rfc6455Protocol = new Rfc6455Protocol();
var self;

function WebSocket(u, headers) {
  self = this;
  var parsedUrl = url.parse(u);
  var secret = crypto.randomBytes(16).toString('base64');
  this.socket = net.connect({
    host: parsedUrl.hostname,
    port: parsedUrl.port
  }, function() {
    self.socket.write('GET ' + parsedUrl.href + ' HTTP/1.1\r\n');
    self.socket.write('Upgrade: websocket\r\n');
    self.socket.write('Connection: Upgrade\r\n');
    self.socket.write('Host: ' + parsedUrl.hostname + '\r\n');
    self.socket.write('Origin: ' + parsedUrl.href + '\r\n');
    self.socket.write('Sec-WebSocket-Key: ' + secret + '\r\n');
    self.socket.write('Sec-WebSocket-Version: 13\r\n');
    Object.keys(headers).forEach(function(k) {
      self.socket.write(util.format('%s: %s\r\n', k, headers[k]));
    });
    this.write('\r\n');
  }).once('data', function(response) {
    response = response.toString();
    response.split('\r\n').forEach(function(line, i) {
      if(i === 0 && !/HTTP\/1\.1 101 Switching Protocols/i.test(line)) {
        throw new Error('Invalid protocol');
      }
      if(!/Sec-WebSocket-Accept/i.test(line)) {
        return;
      }
      var headerSecret = line.split(/Sec-WebSocket-Accept: /i)[1];
      var sha1 = crypto.createHash('sha1');
      sha1.update((secret + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'));
      if(sha1.digest('base64').trim() !== headerSecret) {
        throw new Error('Invalid secret');
      }
    });
    self.socket.pipe(rfc6455Protocol);
    self.emit('connect');
  });
}

util.inherits(WebSocket, events.EventEmitter);

function buildMethod(fn) {
  return function() {
    if(self.closed) {
      return;
    }
    fn.apply(self, Array.prototype.slice.call(arguments));
  };
}

WebSocket.prototype.send = buildMethod(function(data) {
  console.log(data);
  self.socket.write(rfc6455Protocol.buildFrame(new Buffer(data),
    rfc6455Protocol.opcodes.OP_TEXT));
});

WebSocket.prototype.close = buildMethod(function(code, reason) {
  self.socket.write(rfc6455Protocol.buildFrame(reason,
    rfc6455Protocol.opcodes.OP_CLOSE, code));
  self.closed = true;
});

WebSocket.prototype.ping = function(data) {
  self.socket.write(rfc6455Protocol.buildFrame(data,
    rfc6455Protocol.opcodes.OP_PING));
};

