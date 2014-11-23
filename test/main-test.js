
var assert = require('assert'),
    crypto = require('crypto'),
    u2f = require('u2f'),
    u2fhid = require('../'),
    U2FHIDDevice = u2fhid.U2FHIDDevice,
    U2FDevice = u2fhid.U2FDevice;

describe("U2F HID Device", function() {
    var device, deviceInfo;

    it("should enumerate available devices", function() {
        var devices = U2FHIDDevice.enumerate()
        if (devices.length == 0) 
            throw new Error("No U2F devices found.");
        deviceInfo = devices[0];
        assert(deviceInfo);
    });

    it("should open correctly first device", function(done) {
        U2FHIDDevice.open(deviceInfo, function(err, dev) {
            if (err) return done(err);
            device = dev;
            assert(device);
            done();
        });
    });

    it("should respond to ping", function(done) {
        device.ping(done);
    });
    it("should wink if it can", function(done) {
        device.wink(done);
    });
    it("should respond to msg", function(done) {
        device.msg(new Buffer(0), done);
    });

    it("should return error if unknown command", function(done) {
        device.command(0x90, null, function(err) {
            assert(err);
            assert.equal(err.code, 1);
            done();
        });
    });

    after(function() {
        device && device.close();
    });
});

describe("U2F Device interface", function() {
    var device, userDb;
    var appId = "http://demo.com";

    before(function(done) {
        var devices = U2FHIDDevice.enumerate();
        if (devices.length == 0) 
            return done(new Error("No U2F devices found."));
        U2FHIDDevice.open(devices[0], function(err, dev) {
            if (err) return done(err);
            
            device = new U2FDevice(dev);
            done();
        });
    });

    it("should respond to apdu command", function(done) {
        device.command(U2FDevice.U2F_VERSION, done);
    });

    it("should respond to u2f version message", function(done) {
        device.version(function(err, data) {
            if (err) return done(err);
            assert.equal(data.toString(), 'U2F_V2');
            done();
        });
    });

    it("should respond to u2f register message", function(done) {
        this.timeout(35000);

        var req = u2f.request(appId);

        device.register(req, function(err, res) {
            assert.ifError(err);

            var checkres = u2f.checkRegistration(req, res);
            assert(checkres.successful);
            assert(checkres.publicKey);
            assert(checkres.keyHandle);

            userDb = {publicKey: checkres.publicKey, keyHandle: checkres.keyHandle};

            done();
        });
    });

    it("should respond to u2f sign message", function(done) {
        this.timeout(35000);
        var req = u2f.request(appId, userDb.keyHandle);

        device.authenticate(req, function(err, res) {
            assert.ifError(err);
            assert(res);

            var checkres = u2f.checkSignature(req, res, userDb.publicKey);

            assert(checkres.successful);
            done();
        });
    });

    after(function() {
        device && device.close();
    });
});

