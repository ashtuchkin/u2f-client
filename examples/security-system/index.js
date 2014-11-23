var u2fc = require('../../'),
    u2f = require('u2f'),
    fs = require('fs'),
    path = require('path'),
    repl = require('repl'),
    util = require('util'),
    async = require('async'),
    appId = 'node:u2f-client:examples:security-system',
    keyFile = path.join(__dirname, 'keys.json'),
    keys = [];

try {
    keys = JSON.parse(fs.readFileSync(keyFile));
}
catch (e) {}

function saveKeys() {
    fs.writeFileSync(keyFile, JSON.stringify(keys, undefined, 2));
}

// Handle user interaction requests.
u2fc.on('user-presence-required', function() {
    console.log(" -- Please touch the key");
});

u2fc.on('waiting-for-device', function() {
    console.log(" -- Please insert U2F device. Waiting "+u2fc.waitForDevicesTimeout/1000+" sec.");
});

// Capture and handle device connect/disconnect events.
function deviceConnected(device) {
    console.log("\n -- U2F device/key connected");
    async.filterSeries(keys, function(key, cb) {
        u2fc.check(u2f.request(appId, key.keyHandle), function(err, res) {
            if (err) {
                console.error(err);
                return cb(false);
            }
            cb(res);
        });

    }, function(approvedKeys) {
        if (approvedKeys.length == 0) {
            console.log(" -- No user keys found. Register with 'register <username>'.");

        } else if (approvedKeys.length == 1) {
            var key = approvedKeys[0];
            console.log(" -- Key is registered for user '"+key.user+"'. Trying to log in.");
            var req = u2f.request(appId, key.keyHandle);
            u2fc.sign(req, function(err, resp) {
                if (err) return console.error(err);
                var data = u2f.checkSignature(req, resp, key.publicKey);
                if (!data.successful) {
                    console.log(" == ACCESS DENIED == ");
                    console.log(data.errorMessage);
                } else {
                    console.log(" == ACCESS GRANTED for user "+key.user+" == ")
                }
            });

        } else {
            console.log(" -- Key is registered for users: "+ approvedKeys.map(function(k) {return k.user}).join(", "));
            console.log(" -- Type 'login <username>' with one of these usernames to get access.");
        }
    });
}

function deviceDisconnected(deviceId) {
    console.log("\n -- U2F device/key disconnected");
}

// Poll for changes in devices array.
var devicesSeen = {};
setInterval(function() {
    var devices = u2fc.devices();
    for (var i = 0; i < devices.length; i++) {
        var id = devices[i].id;
        if (!devicesSeen[id])
            setTimeout(deviceConnected, 0, devices[i]);
        else
            delete devicesSeen[id];
    }
    for (var k in devicesSeen)
        deviceDisconnected(k);

    devicesSeen = {};
    for (var i = 0; i < devices.length; i++)
        devicesSeen[devices[i].id] = true;
}, 200);


// Launch the REPL.
console.log("Welcome to U2F Security System example. Insert U2F key and touch it to get access granted.");
console.log("Type 'register <user>' to register currently inserted U2F device as belonging to given user.");
console.log("Type 'help' for other commands. Ctrl-D to exit.");
console.log("Registration data is kept in 'keys.json' file.");

repl.start({
    eval: function(cmd, context, filename, cb) {
        cmd = cmd.slice(1, -2).split(' ').filter(Boolean);
        if (cmd.length === 0) {
            cb();

        } else if (cmd[0] === 'register' && cmd[1]) {
            var user = cmd[1];

            // Create registration request using U2F client module and send to device.
            var registerRequest = u2f.request(appId);
            u2fc.register(registerRequest, function(err, resp) {
                if (err) return cb(err);
                
                // Check response is valid.
                var keyData = u2f.checkRegistration(registerRequest, resp);
                if (!keyData.successful)
                    return cb(new Error(keyData.errorMessage));

                keys.push({
                    user: user,
                    keyHandle: keyData.keyHandle,
                    publicKey: keyData.publicKey,
                });
                saveKeys();
                console.log('User '+user+' registered successfully');
                cb();
            });

        } else if (cmd[0] === 'login' && cmd[1]) {
            var user = cmd[1];
            var userKeys = keys.filter(function(key) {return key.user === user;});
            if (userKeys.length == 0) {
                console.log("Unknown user.");
                return cb();
            }
            async.filterSeries(userKeys, function(key, cb) {
                u2fc.check(u2f.request(appId, key.keyHandle), function(err, res) {
                    if (err) {
                        console.error(err);
                        return cb(false);
                    }
                    cb(res);
                });
            }, function(approvedKeys) {
                if (approvedKeys.length == 0) {
                    console.log("No applicable keys found.");
                    return cb();
                }
                var key = approvedKeys[0];
                var req = u2f.request(appId, key.keyHandle);
                u2fc.sign(req, function(err, resp) {
                    if (err) return cb(err);
                    var data = u2f.checkSignature(req, resp, key.publicKey);
                    if (!data.successful) {
                        console.log(" == ACCESS DENIED == ");
                        console.log(data.errorMessage);
                    } else {
                        console.log(" == ACCESS GRANTED for user "+key.user+" == ")
                    }
                });
            });

        } else if (cmd[0] === 'remove' && cmd[1]) {
            var user = cmd[1];
            var newKeys = keys.filter(function(key) {return key.user !== user;});
            if (newKeys.length == keys.length) {
                console.log("No keys for user '"+user+"' found.");
            } else {
                console.log((keys.length-newKeys.length)+" keys removed.");
                keys = newKeys;
                saveKeys();
            }
            cb();

        } else if (cmd[0] === 'help') {
            console.log("Commands available:");
            console.log("  help             Prints this message");
            console.log("  register <user>  Registers given user with currently connected device");
            console.log("  login <user>     Try to log in as a given user");
            console.log("  remove <user>    Clears access for given user");
            console.log("  users            Prints registered users");
            console.log("  devices          Prints currently connected devices");
            cb();

        } else if (cmd[0] === 'users') {
            var users = {};
            for (var i = 0; i < keys.length; i++)
                users[keys[i].user] = true;
            console.log("Registered users: "+(Object.keys(users).join(", ") || 'none'));
            cb();

        } else if (cmd[0] === 'devices') {
            cb(null, u2fc.devices());

        } else {
            cb(null, "Unknown command. Type 'help' to get all available commands.");
        }
    },
    ignoreUndefined: true,

}).on('exit', function() {
    console.log();
    process.exit();
});

