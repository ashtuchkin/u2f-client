"use strict";

var hid = require('node-hid'),
    crypto = require('crypto'),
    events = require('events'),
    util = require('util');

// HID driver for U2F Devices.
// Specification: https://fidoalliance.org/specs/fido-u2f-HID-protocol-v1.0-rd-20141008.pdf
// rawDevice is Node v0.8-style stream (with 'data', 'error' events and .write(), .close()) 
//   that speaks HID protocol to hardware. Luckily, hid.HID() conforms to this spec.
// initCb is called when the device is initialized with either error or this object itself. 
var U2FHIDDevice = module.exports = function U2FHIDDevice(rawDevice, initCb) {
    events.EventEmitter.call(this);

    this.device = rawDevice;

    this.protocolVersion = 0;
    this.deviceVersion = [0, 0, 0];
    this.caps = {};
    this.closed = false;

    this._channelId = U2FHIDDevice.U2FHID_BROADCAST_CID;
    this._reportSize = 64;
    this._packetBuf = new Buffer(this._reportSize);

    this._queue = [];
    this._curTransaction = undefined;

    this._onError = this._onError.bind(this);
    this._onData  = this._onData.bind(this)
    this.device.on('error', this._onError);  // 'error' should be first because polling starts when 'data' is bound
    this.device.on('data', this._onData);

    this._init(initCb);
}

util.inherits(U2FHIDDevice, events.EventEmitter);

// Canonical usage page and usage of U2F HID devices.
U2FHIDDevice.FIDO_USAGE_PAGE = 0xF1D0;
U2FHIDDevice.FIDO_USAGE_U2FHID = 1;

// Enumerate compatible devices (if acceptFn is null) or all that are accepted by acceptFn.
// acceptFn is called with (deviceInfo, defaultResult) parameters. Should return true/false.
// Callback returns array of deviceInfo-s, with unique id-s.
// Sample deviceInfo: {
//     id: 'USB_1050_0120_14200000',
//     vendorId: 4176,
//     productId: 288,
//     path: 'USB_1050_0120_14200000',
//     serialNumber: '',
//     manufacturer: 'Yubico',
//     product: 'Security Key by Yubico',
//     release: 819,
//     interface: -1,
//     usagePage: 61904,
//     usage: 1 
// }
U2FHIDDevice.enumerate = function enumerate(acceptFn) {
    return hid.devices().filter(function(deviceInfo) {
        deviceInfo.id = deviceInfo.path; // Add unique identifier to deviceInfo to help distinguishing them.
        var isCompatible = (deviceInfo.usagePage == U2FHIDDevice.FIDO_USAGE_PAGE && 
               deviceInfo.usage == U2FHIDDevice.FIDO_USAGE_U2FHID);

        if (acceptFn)
            isCompatible = acceptFn(deviceInfo, isCompatible);

        return isCompatible;
    });
}

// Open & initialize device using provided deviceInfo.
U2FHIDDevice.open = function open(deviceInfo, cb) {
    var rawDevice;
    try {
        rawDevice = new hid.HID(deviceInfo.path);
        rawDevice.info = deviceInfo; // Save information about device for further reference.
    }
    catch (e) {
        cb(e); // ~ "cannot open device with path USB_1050_0120_14200000"
        return;        
    }

    new U2FHIDDevice(rawDevice, cb); // cb will return error or device itself.
}

// Commands to U2F HID devices.
U2FHIDDevice.U2FHID_PING =          0x80 | 0x01;
U2FHIDDevice.U2FHID_MSG =           0x80 | 0x03;
U2FHIDDevice.U2FHID_LOCK =          0x80 | 0x04;
U2FHIDDevice.U2FHID_INIT =          0x80 | 0x06;
U2FHIDDevice.U2FHID_WINK =          0x80 | 0x08;
U2FHIDDevice.U2FHID_SYNC =          0x80 | 0x3C;
U2FHIDDevice.U2FHID_ERROR =         0x80 | 0x3F;
U2FHIDDevice.U2FHID_VENDOR_FIRST =  0x80 | 0x40;
U2FHIDDevice.U2FHID_VENDOR_LAST  =  0x80 | 0x7F;

U2FHIDDevice.U2FHID_BROADCAST_CID = 0xffffffff;

var hidErrors = {
    0x00: "No error",
    0x01: "Invalid command",
    0x02: "Invalid parameter",
    0x03: "Invalid message length",
    0x04: "Invalid message sequencing",
    0x05: "Message has timed out",
    0x06: "Channel busy",
    0x0a: "Command requires channel lock",
    0x0b: "SYNC command failed",
    0x7f: "Other unspecified error",
};

// Initialize HID device.
U2FHIDDevice.prototype._init = function(cb, forSure) {
    var nonce = crypto.pseudoRandomBytes(8);
    var that = this;
    this.command(U2FHIDDevice.U2FHID_INIT, nonce, function(err, data) {
        if (err)
            return cb(new Error("Error initializing U2F HID device: " + err.message));

        // Check nonce.
        var nonce2 = data.slice(0, 8);
        if (nonce.toString('hex') != nonce2.toString('hex'))
            // TODO: Probably we just need to ignore it because other client could have tried to initialize same key with different nonce.
            return cb(new Error("Error initializing U2F HID device: incorrect nonce"));

        // Decode other initialization data.
        try {
            that._channelId = data.readUInt32BE(8);
            that.protocolVersion = data.readUInt8(12);
            that.deviceVersion = [data.readUInt8(13), data.readUInt8(14), data.readUInt8(15)];
            that.capsRaw = data.readUInt8(16);
            that.caps = {
                wink: !!(that.capsRaw & 0x01),
            };
        }
        catch (e) {
            cb(new Error("Error initializing U2F HID device: returned initialization data too short."));
            return;
        }

        // Check protocol version is compatible.
        if (that.protocolVersion != 2) {
            cb(new Error("Error initializing U2F HID device: incompatible protocol version: "+that.protocolVersion));
            return;
        }

        if ((that._channelId >>> 24) == 0 && !forSure) {
            // Some buggy keys give unacceptable channel_ids the first time (which don't work for following commands), so we try again.
            that._channelId = U2FHIDDevice.U2FHID_BROADCAST_CID;
            that._init(cb, true); 
        }
        else
            cb(null, that); // Successful initialization.
    });
}

// Packetize & send raw command request.
// command - one of U2FHID_*
// data can be empty/null or buffer.
U2FHIDDevice.prototype._sendCommandRequest = function(command, data) {
    if (!data)
        data = new Buffer(0);
    if (!(0x80 <= command && command < 0x100))
        throw new Error("Tried to send incorrect U2F HID command: "+command);

    // Create & send initial packet.
    var buf = this._packetBuf;
    buf.fill(0);
    buf.writeUInt32BE(this._channelId, 0);
    buf.writeUInt8(command, 4);
    buf.writeUInt16BE(data.length, 5);
    data.copy(buf, 7); data = data.slice(buf.length - 7);
    this.device.write(buf);

    // Create & send continuation packets.
    var seq = 0;
    while (data.length > 0 && seq < 0x80) { 
        buf.fill(0);
        buf.writeUInt32BE(this._channelId, 0);
        buf.writeUInt8(seq++, 4);
        data.copy(buf, 5); data = data.slice(buf.length - 5);
        this.device.write(buf);
    }
    if (data.length > 0)
        throw new Error("Tried to send too large data packet to U2F HID device ("+data.length+" bytes didn't fit).");
}

// Starts next transaction from the queue. Warning, this overwrites the _curTransaction.
U2FHIDDevice.prototype._sendNextTransaction = function() {
    if (this._queue.length == 0) {
        this._curTransaction = undefined;
        return;
    }

    var t = this._curTransaction = this._queue.shift();
    try {
        this._sendCommandRequest(t.command, t.data);
    }
    catch(e) {
        // Can be either incorrect command/data, or the device is failed/disconnected ("Cannot write to HID device").
        // In the latter case, an 'error' event will be emitted soon.
        // TODO: We're probably in an inconsistent state now. Maybe we need to U2FHID_SYNC.
        if (t.cb) t.cb(e); // Transaction errored.
        t.cb = null; // Don't call callback anymore.
        
        this._sendNextTransaction(); // Process next one.
    }
}

// A packet received. Decode & process it.
// TODO: if the buf is smaller then needed, we might end in inconsistent state.
//       we need to error out transaction and SYNC.
U2FHIDDevice.prototype._onData = function(buf) {
    var t = this._curTransaction;

    if (!t) return; // Ignore packets outside the transaction.

    // Decode packet
    var channelId = buf.readUInt32BE(0);
    if (channelId !== this._channelId)
        return; // Ignore packet addressed to other channels.

    var cmd = buf.readUInt8(4);
    if (cmd === U2FHIDDevice.U2FHID_ERROR) { // Errored.
        var errCode = buf.readUInt8(7);
        var error = new Error(hidErrors[errCode] || hidErrors[0x7f]);
        error.code = errCode;
        if (t.cb) t.cb(error);
        t.cb = null;

        this._sendNextTransaction();
    }
    else if (cmd & 0x80) { // Initial packet
        if (cmd !== t.command)
            return console.error("Transaction decoding failure: response is for different operation: ", cmd, t);

        t.toReceive = buf.readUInt16BE(5);
        t.receivedBufs[0] = buf.slice(7);
        t.receivedBytes += t.receivedBufs[0].length;
    }
    else { // Continuation packet.
        t.receivedBufs[cmd+1] = buf.slice(5);
        t.receivedBytes += t.receivedBufs[cmd+1].length;
    }

    // Call callback and finish transaction if read fully.
    if (t.receivedBytes >= t.toReceive) {
        if (t.cb)
            t.cb(null, Buffer.concat(t.receivedBufs).slice(0, t.toReceive));
        t.cb = null;

        this._sendNextTransaction();
    }
}

// Device is errored. Most likely it's because it was disconnected. Close it.
U2FHIDDevice.prototype._onError = function(err) {
    // 'data' events are paused at this point, we could do this.device.resume(), 
    // but the device is in inconsistent state anyway.
    this.close();
    this.emit('disconnected');
}


// Main interface: queue a raw command.
// TODO: Timeout.
U2FHIDDevice.prototype.command = function(command, data, cb) {
    if (this.closed)
        return cb(new Error("Tried to queue a command for closed device."));
    
    // Add transaction to the queue.
    this._queue.push({
        command: command, 
        data: data, 
        cb: cb,
        toReceive: 0xffff,
        receivedBytes: 0,
        receivedBufs: [],
    });

    if (!this._curTransaction)
        this._sendNextTransaction();
}

// Close device when it's not needed anymore.
U2FHIDDevice.prototype.close = function() {
    if (this.closed) return;
    this.closed = true;
    // TODO: Cleanup the queue.

    this.device.close();
    this.device.removeListener('error', this._onError);
    this.device.removeListener('data', this._onData);
    this.emit('closed');
};


// Higher level interface
U2FHIDDevice.prototype.ping = function(data, cb) {  // U2FHID_PING
    if (!cb) { cb = data; data = undefined; }
    if (typeof data === 'number') data = new Buffer(data);
    this.command(U2FHIDDevice.U2FHID_PING, data, cb);
}

U2FHIDDevice.prototype.wink = function(cb) {       // U2FHID_WINK
    if (this.caps.wink)
        this.command(U2FHIDDevice.U2FHID_WINK, null, cb);
    else if (cb)
        cb();
}

U2FHIDDevice.prototype.msg = function(data, cb) {  // U2FHID_MSG
    this.command(U2FHIDDevice.U2FHID_MSG, data, cb);
}




