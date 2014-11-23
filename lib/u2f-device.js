"use strict";

var crypto = require('crypto'),
    events = require('events'),
    util = require('util');

// U2F Device raw interface.
// https://fidoalliance.org/specs/fido-u2f-raw-message-formats-v1.0-rd-20141008.pdf
var U2FDevice = module.exports = function U2FDevice(driver) {
    events.EventEmitter.call(this);

    this.driver = driver;
    if (driver.protocolVersion != 2)
        throw new Error("Driver has unsupported protocol version: "+driver.protocolVersion+". Only 2 suported.")

    this.driver.on('disconnected', this._onDisconnected.bind(this));
}

util.inherits(U2FDevice, events.EventEmitter);

U2FDevice.prototype._onDisconnected = function() {
    this.emit('disconnected');
}

U2FDevice.prototype.close = function() {
    this.driver.close();
}

U2FDevice.prototype.interactionTimeout = 30000;
U2FDevice.prototype.interactionPollInterval = 200;

var ErrorCodes = U2FDevice.ErrorCodes = {
    SW_NO_ERROR: 0x9000,
    SW_WRONG_LENGTH: 0x6700,
    SW_CONDITIONS_NOT_SATISFIED: 0x6985,
    SW_WRONG_DATA: 0x6a80,
    SW_INS_NOT_SUPPORTED: 0x6d00,
};


// Send raw U2F Command using APDU message exchange protocol.
// p1, p2 and data args are optional.
U2FDevice.prototype.command = function(cmd, p1, p2, data, cb) {
    if (!cb) { cb = data; data = p2; p2 = 0; }
    if (!cb) { cb = data; data = p1; p1 = 0; }
    if (!cb) { cb = data; data = new Buffer(0); }

    // Create APDU Request frame
    var buf = new Buffer(data.length+7);
    buf[0] = 0; // CLA
    buf[1] = cmd; // INS
    buf[2] = p1; // P1
    buf[3] = p2; // P2
    buf[4] = 0; // LC1 (MSB)
    buf.writeUInt16BE(data.length, 5); // LC2, LC3 (LSB)
    data.copy(buf, 7);

    var that = this,
        startTime = Date.now(),
        userPresenceEventSent = false;

    (function sendCommand() {
        // Send command to the driver.
        that.driver.msg(buf, function(err, res) {
            if (err) return cb(err);
            if (res.length < 2) return cb(new Error("Cannot decode APDU: returned data too short."));

            // Decode APDU frame status
            var status = res.readUInt16BE(res.length-2);

            if (status == ErrorCodes.SW_NO_ERROR) {  // Success; return data
                cb(null, res.slice(0, -2));

            } else if (status == ErrorCodes.SW_CONDITIONS_NOT_SATISFIED
                    && !(p1 & 0x04) && (Date.now() - startTime < that.interactionTimeout)) {  
                // We need user presence, but don't have it.
                // Wink and retry.
                if (!userPresenceEventSent) {
                    that.emit('user-presence-required');
                    userPresenceEventSent = true;
                }            
                that.driver.wink();
                setTimeout(sendCommand, that.interactionPollInterval);

            } else {
                var message;
                for (var name in ErrorCodes)
                    if (ErrorCodes[name] === status)
                        message = name;
                if (!message)
                    message = "SW_UNKNOWN_ERROR: 0x"+status.toString(16)
                var err = new Error(message);
                err.code = status;
                return cb(err);
            }
        });
    })();
}


// Raw U2F commands
U2FDevice.U2F_REGISTER     = 0x01; // Registration command
U2FDevice.U2F_AUTHENTICATE = 0x02; // Authenticate/sign command
U2FDevice.U2F_VERSION      = 0x03; // Read version string command

U2FDevice.U2F_VENDOR_FIRST = 0xC0; 
U2FDevice.U2F_VENDOR_LAST  = 0xFF;

U2FDevice.U2F_AUTH_ENFORCE    = 0x03; // Enforce user presence and sign
U2FDevice.U2F_AUTH_CHECK_ONLY = 0x07; // Check only


U2FDevice.prototype.version = function(cb) {
    this.command(U2FDevice.U2F_VERSION, cb);
}

U2FDevice.prototype.register = function(req, callback) {
    var clientData = JSON.stringify({
        typ: "navigator.id.finishEnrollment",
        challenge: req.challenge,
        origin: req.appId, // We use appId as origin as differentiation doesn't make sense here.
    });
    
    var buf = Buffer.concat([hash(clientData), hash(req.appId)]);
    this.command(U2FDevice.U2F_REGISTER, buf, function(err, data) {
        if (err)
            return callback(err);

        callback(null, {
            registrationData: websafeBase64(data),
            clientData: websafeBase64(clientData)
        });
    });
}

U2FDevice.prototype.authenticate = function(req, callback) {
    var clientData = JSON.stringify({
        typ: "navigator.id.getAssertion",
        challenge: req.challenge,
        origin: req.appId, // We use appId as origin as differentiation doesn't make sense here.
    });
    var keyHandle = new Buffer(req.keyHandle, 'base64');

    var buf = Buffer.concat([hash(clientData), hash(req.appId), new Buffer([keyHandle.length]), keyHandle]);
    this.command(U2FDevice.U2F_AUTHENTICATE, U2FDevice.U2F_AUTH_ENFORCE, buf, function(err, data) {
        if (err)
            return callback(err);

        callback(null, {
            keyHandle: req.keyHandle,
            signatureData: websafeBase64(data),
            clientData: websafeBase64(clientData)
        });
    });
}

U2FDevice.prototype.checkKeyRecognized = function(req, callback) {
    var clientData = ''; // it will not be signed anyway.
    var keyHandle = new Buffer(req.keyHandle, 'base64');

    var buf = Buffer.concat([hash(clientData), hash(req.appId), new Buffer([keyHandle.length]), keyHandle]);
    this.command(U2FDevice.U2F_AUTHENTICATE, U2FDevice.U2F_AUTH_CHECK_ONLY, buf, function(err, data) {
        if (err.code == ErrorCodes.SW_CONDITIONS_NOT_SATISFIED) // device recognizes given keyHandle
            return callback(null, true); 
        if (err.code == ErrorCodes.SW_WRONG_DATA) // keyHandle not recognized
            return callback(null, false);

        callback(err); // Some other error, like timeout.
    });
}



// =============================================================================
// Utils

function websafeBase64(buf) {
    if (!Buffer.isBuffer(buf))
        buf = new Buffer(buf);
    return buf.toString('base64').replace(/\//g,'_').replace(/\+/g,'-').replace(/=/g, '');
}

function hash(buf) {
    return crypto.createHash('SHA256').update(buf).digest();
}

