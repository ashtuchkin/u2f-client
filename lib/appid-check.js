
var psl = require('psl'),
    url = require('url'),
    async = require('async'),
    request = require('request');


// Checks all appIds in given requests are compatible with given facetId (origin).
// See https://fidoalliance.org/specs/fido-appid-and-facets-v1.0-rd-20141008.pdf  (Section 3.1.2)
// facetId is either a web origin uri with empty path and default port removed (http://example.com/),
// or a custom scheme uri for mobile applications.
module.exports = function checkAppIds(facetId, version, requests, cb) {
    if (!facetId)
        return cb(new Error("missing facetId"));

    if (!requests)
        return cb(new Error("missing requests"));
    if (requests.length == 0)
        return cb(null, true);

    async.every(requests, function(request, cb) {
        var appId = request.appId;
        var app = url.parse(appId);
        var facet = url.parse(facetId);

        if (app.protocol !== 'https:' && appId === facetId)
            return cb(true); // Trivial match

        if (!appId) {
            request.appId = facetId;
            return cb(true); // Set appId when it's not set.
        }

        if (facet.protocol === 'https:' && facet.hostname === app.hostname)
            return cb(true); // Same host names and secure protocol.

        if (app.protocol !== 'https:')
            return cb(false); // We don't fetch non-secure resources.

        // Request appId and check it has facetId mentioned.
        request({
            url: appId, json: true, strictSSL: true, timeout: 3000, 
            redirect: function(resp) {
                return resp.headers["FIDO-AppID-Redirect-Authorized".toLowerCase()] == 'true';
            },
        }, function(err, resp, body) {
            if (err || resp.statusCode !== 200)
                return cb(false);
            if (resp.headers['content-type'] != 'application/fido.trusted-apps+json')
                return cb(false);
            if (!body || !body.trustedFacets || !body.trustedFacets.length)
                return cb(false);

            var trustedFacets = Array.prototype.filter.call(body.trustedFacets, function(tf) {
                return tf.version == version || (tf.version && tf.version.major == version);
            })[0];
            if (!trustedFacets || !trustedFacets.ids || !trustedFacets.ids.length)
                return cb(false);
            
            for (var i = 0; i < trustedFacets.ids.length; i++) {
                var id = trustedFacets.ids[i];
                var parsed = url.parse(id);
                if (parsed.protocol === 'https:') {
                    // Remove any path, query, etc.
                    var id = url.format({protocol: parsed.protocol, hostname: parsed.hostname, port: parsed.port, path: '/'});
                    if (etldplus1(id) === etldplus1(appId) && id === facetId)
                        return cb(true);
                }
                else if (parsed.protocol !== 'http:') { // other protocols.
                    if (id === facetId)
                        return cb(true);
                }
            }
            cb(false);
        });

    }, function(res) {
        if (res) cb(null, true);
        else cb(new Error('bad appId'));
    });
}

function etldplus1(uri) {
    var domain = url.parse(uri, false, true).hostname;
    var parsed = psl.parse(domain);
    return parsed.sld+'.'+parsed.tld;
}

