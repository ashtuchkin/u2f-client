# U2F-Client: Access U2F/USB keys directly, without browser

For a general description, please see [Universal Second Factor authentication](https://fidoalliance.org/specifications/).
This module provides FIDO client functionality: it provides access to available 
USB/HID hardware keys (role that usually filled by a web browser).

Using this module, you can build a hardware security system with U2F keys authentication, or provide
U2F interface in browser emulation.

To create and check register/sign requests, please see other module: [u2f](https://github.com/ashtuchkin/u2f).

## Features
 * Straightforward, node.js style API: callbacks & events.
 * Supports all OS-es via excellent node-hid module.
 * Supports standard U2F Javascript API for browsers, checking facetId etc.

## Usage
```javascript
var u2fc = require('u2f-client');

// High-level API 
// registerRequest and signRequest, as well as returned values are specified in U2F documentation
u2fc.register(registerRequest, cb)   // Register U2F device, requires user presence
u2fc.sign(signRequest, cb)           // Signs with U2F device, requires user presence
u2fc.check(signRequest, cb)          // Check if signRequest is acceptable, doesn't require user presence. Returns true or false.
u2fc.devices()                       // Returns array of connected deviceInfo-s.

// Events
u2fc.on 'waiting-for-device'     // Request user to insert a U2F device, as there's no devices found
u2fc.on 'user-presence-required' // Request user to touch the U2F device (issued after register or sign requests)



// U2F Javascript API for Web Browsers 
// Careful, the callback convention is different - both error and result come as first and only argument.
// Origin of the requesting party must be provided and will be checked according to the spec rules.
browserU2F = u2fc.browserApi(origin)
browserU2F.register(registerRequests, signRequests, callback, opt_timeout)
browserU2F.sign(signRequests, callback, opt_timeout)


// Options
u2fc.waitForDevicesTimeout = 10000 // How much time should we wait if no device present.
u2fc.userPresenceTimeout = 10000   // How much time to wait for pressing the button on device.

```

## Examples
 * [REPL security system](https://github.com/ashtuchkin/u2f-client/tree/master/examples/security-system)

### TODO
 * it seems linux doesn't provide usage & usagePage information -> use hardcoded vendorId/productId table?
 * provide more consistency with respect to concurrent usage at the driver level (login+insert key fails), + don't close device every time.
 * provide 'disconnected' event on client.
 * test U2FClient, browser api.
 * comprehensive timeouts: low-level and BrowserAPI
 * command-line interface? (u2f sign, u2f register) maybe another module?


License: MIT
