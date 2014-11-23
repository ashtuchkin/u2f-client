
var EventEmitter = require('events').EventEmitter,
    util = require('util'),
    async = require('async'),
    U2FHIDDevice = require('./u2f-hid-device'),
    U2FDevice = require('./u2f-device'),
    browserApi = require('./browser-api');


var U2FClient = module.exports = function U2FClient(options) {
    EventEmitter.call(this);
    this.drivers = [U2FHIDDevice];
    this.waitForDevicesTimeout = 10000;
    this.userPresenceTimeout = 10000;
    this.protocolVersion = "U2F_V2"; // Todo: get it from device.
}

util.inherits(U2FClient, EventEmitter);

U2FClient.prototype.devices = function(acceptFn) {
    if (Date.now() - (this._deviceCacheTime || 0) < 50)
        return this._deviceCache;

    var that = this;
    this._deviceCache = Array.prototype.concat.apply([],
        this.drivers.map(function(driver) {
            return driver.enumerate(that.acceptFn.bind(that, driver))
                .map(function(deviceInfo) {
                    Object.defineProperty(deviceInfo, '_driver', {value: driver}); // Non-enumerable to avoid util.inspect()
                    return deviceInfo;
                });
        })
    );
    this._deviceCacheTime = Date.now();
    return this._deviceCache;
}

U2FClient.prototype.acceptFn = function(driver, deviceInfo, defAccept) {
    return defAccept;
}

U2FClient.prototype.register = function(req, cb) {
    this._doWithDevices(function(device, cb) {
        device.register(req, cb);
    }, cb);
}

U2FClient.prototype.sign = function(req, cb) {
    this._doWithDevices(function(device, cb) {
        device.authenticate(req, cb);
    }, cb);
}

// Returns if current key(s) can sign provided request.
U2FClient.prototype.check = function(req, cb) {
    var that = this;
    this.waitForDevices(function(err, devices) {
        if (err) return cb(err);
        async.map(devices, function(deviceInfo, cb) {
            deviceInfo._driver.open(deviceInfo, function(err, rawdevice) {
                if (err) return cb(err);
                var device = new U2FDevice(rawdevice);
                device.checkKeyRecognized(req, function(err, resp) {
                    device.close();
                    cb(err, resp);
                });
            });
        }, function(err, resp) {
            if (err) return cb(err);
            cb(null, resp.some(Boolean));
        });
    });
}

U2FClient.prototype.browserApi = function(origin) {
    return new BrowserApi(this, origin);
}


U2FClient.prototype._doWithDevices = function(fn, cb) {
    var that = this, 
        eventEmitted = false;
    this.waitForDevices(function(err, devices) {
        if (err) return cb(err);
        var _err, results = {};
        async.detect(devices, function(deviceInfo, cb) {
            deviceInfo._driver.open(deviceInfo, function(err, rawdevice) {
                if (err) return _err = err, cb(false);
                var device = new U2FDevice(rawdevice);
                device.interactionTimeout = that.userPresenceTimeout;
                device.on('user-presence-required', function() {
                    if (!eventEmitted) {
                        that.emit('user-presence-required');
                        eventEmitted = true;
                    }
                });
                fn(device, function(err, resp) {
                    device.close();
                    if (err) return _err = err, cb(false);
                    results[deviceInfo.id] = resp;
                    cb(true);
                })
            });
        }, function(deviceInfo) {
            if (deviceInfo) cb(null, results[deviceInfo.id]);
            else cb(_err);
        });
    });
}

U2FClient.prototype.waitForDevices = function(cb, timeout) {
    if (typeof timeout === 'undefined')
        timeout = this.waitForDevicesTimeout;

    var startTime = Date.now(),
        that = this,
        eventEmitted = false;
    (function poll() {
        var devices = that.devices();
        if (devices.length > 0)
            return cb(null, devices);

        if (Date.now() - startTime > that.waitForDevicesTimeout)
            return cb(new Error('Timed out waiting for U2F device'));

        if (!eventEmitted) {
            that.emit('waiting-for-device');
            eventEmitted = true;
        }

        setTimeout(poll, that.waitForDevicesPollInterval || 200);
    })();
}

