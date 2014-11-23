
var U2FClient = require('./lib/u2f-client.js');

module.exports = new U2FClient();

module.exports.U2FClient = U2FClient;
module.exports.U2FDevice = require('./lib/u2f-device.js');
module.exports.U2FHIDDevice = require('./lib/u2f-hid-device.js');
module.exports.BrowserApi = require('./lib/browser-api.js');
