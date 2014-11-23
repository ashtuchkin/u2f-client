var async = require('async'),
    appIdCheck = require('./appid-check'),
    U2FDevice = require('./u2f-device');

var BrowserApi = module.exports = function BrowserApi(client, origin) {
    this.client = client;
    this.origin = origin;
}

var ErrorCodes = BrowserApi.ErrorCodes = {
    OTHER_ERROR: 1,
    BAD_REQUEST: 2,
    CONFIGURATION_UNSUPPORTED: 3,
    DEVICE_INELIGIBLE: 4,
    TIMEOUT: 5,
};


BrowserApi.prototype.register = function register(registerRequests, signRequests, callback, opt_timeoutSeconds) {
    if (!registerRequests || !registerRequests.length)
        return callback(webError(ErrorCodes.BAD_REQUEST, "No register request objects found"));

    var client = this.client, that = this;
    registerRequests = registerRequests.filter(function(req) {return req.version == client.protocolVersion; });
    signRequests    =(signRequests||[]).filter(function(req) {return req.version == client.protocolVersion; });

    // Check & apply sign requests
    if (signRequests.length > 0) {
        appIdCheck(this.origin, client.protocolVersion, signRequests, function(err) {
            if (err) return callback(webError(ErrorCodes.BAD_REQUEST, err.message));
            async.mapSeries(signRequests, client.check.bind(client), function(err, res) {
                if (err) return callback(toWebError(err));
                if (res.some(Boolean)) return callback(webError(ErrorCodes.DEVICE_INELIGIBLE, "Register request invalid: signRequests contains valid key."));

                // No valid sign requests found. Retry without them.
                that.register(registerRequests, [], callback, opt_timeout);
            });
        });
        return;
    }

    // Attempt register operation.
    if (!registerRequests.length)
        return callback(webError(ErrorCodes.CONFIGURATION_UNSUPPORTED, "No register requests with supported u2f versions found"));

    // Only first register request is tried.
    registerRequests.length = 1;
    appIdCheck(this.origin, client.protocolVersion, registerRequests, function(err) {
        if (err) return callback(toWebError(err));
        client.register(registerRequests[0], function(err, data) {
            if (err) return callback(toWebError(err));
            callback(data);
        });
    });
}


BrowserApi.prototype.sign = function sign(signRequests, callback, opt_timeoutSeconds) {
    if (!signRequests || !signRequests.length)
        return callback(webError(ErrorCodes.BAD_REQUEST, "No sign request objects found"));

    var client = this.client, that = this;
    signRequests = signRequests.filter(function(req) {return req.version == client.protocolVersion; });

    if (signRequests.length == 0)
        return callback(webError(ErrorCodes.DEVICE_INELIGIBLE, "No applicable sign requests given"));

    // Check & apply sign requests
    appIdCheck(this.origin, client.protocolVersion, signRequests, function(err) {
        if (err) return callback(webError(ErrorCodes.BAD_REQUEST, err.message));

        var _err, _res;
        async.detectSeries(signRequests, function(req, cb) {
            client.sign(req, function(err, res) {
                if (err && err.code === U2FDevice.ErrorCodes.SW_WRONG_DATA)
                    return cb(false);
                if (err)
                    return _err = err, cb(true);
                _res = res;
                cb(true);
            });
        }, function(res) {
            if (res) {
                if (_err) return callback(toWebError(_err));
                callback(_res);
            }
            else
                return callback(webError(ErrorCodes.DEVICE_INELIGIBLE, "Sign request invalid: no valid keyHandles supplied."));
        });
    });
}

function webError(code, message) {
    return {
        errorCode: code || ErrorCodes.OTHER_ERROR,
        errorMessage: message,
    };
}


function toWebError(err) {
    switch (err.code) {
        case U2FDevice.ErrorCodes.SW_WRONG_LENGTH, 
             U2FDevice.ErrorCodes.SW_WRONG_DATA:
            return webError(ErrorCodes.BAD_REQUEST);

        case U2FDevice.ErrorCodes.SW_CONDITIONS_NOT_SATISFIED:
            return webError(ErrorCodes.TIMEOUT);

        default:
            if (/Timed out/.test(err.message))
                return webError(ErrorCodes.TIMEOUT, err.message);
            else
                return webError(ErrorCodes.OTHER_ERROR, err.message);
    }
}





