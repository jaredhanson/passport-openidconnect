/**
 * Module dependencies.
 */
var url = require('url')
  , querystring = require('querystring')
  , http = require('http')
  , https = require('https')
  , util = require('util');


/**
 * Register with an OpenID Connect provider.
 *
 * OpenID Connect is an identity layer on top of OAuth 2.0.  OAuth 2.0 requires
 * a client identifier (and corresponding secret) registered at the
 * authorization server.  To facilitate a more "federated" approach to
 * authentication, an OpenID Connect provider may implement an open registration
 * endpoint, in order to issue client IDs on an as-needed basis.
 *
 * This module implements support for dynamically registering with an OpenID
 * provider during authentication.  The registration information should be
 * persisted by the application, so that it can be reused in subsequent attempts
 * to authenticate with the same provider.
 *
 * References:
 *   - [OpenID Connect Dynamic Client Registration 1.0 - draft 14](http://openid.net/specs/openid-connect-registration-1_0.html)
 *
 * @return {Function}
 * @api public
 */
module.exports = function(options, save) {
  options = options || {};

  return function(provider, done) {

    ////////////////////////////

    var parsed = url.parse(provider.registrationURL)
      , path
      , headers = {}
      , body;

    path = parsed.pathname;

    headers['Host'] = parsed.host;
    headers['Content-Type'] = 'application/x-www-form-urlencoded';
    headers['Accept'] = 'application/json';

    body = querystring.stringify(params);

    var opts = {
      host: parsed.hostname,
      port: parsed.port,
      path: path,
      method: 'POST',
      headers: headers
    };

    // TODO: Add option to allow http requests (disabled by default).
    var req = https.request(opts, function(res) {
      var data = '';

      res.on('data', function(chunk) {
        data += chunk;
      });
      res.on('end', function() {
        if (res.statusCode !== 200) {
          // TODO: Parse error information for diagnostic purposes.
          return done(new Error("OpenID dynamic client registration request failed: " + res.statusCode));
        }

        var reg = {};
        try {
          var json = JSON.parse(data);

          reg.clientID = json.client_id;
          reg.clientSecret = json.client_secret;
          reg.accessToken = json.registration_access_token;
          reg.expiresAt = json.expires_at;

          reg._raw = json;

          save(provider, reg, function(err) {
            if (err) { return done(err); }
            return done(null, reg);
          });
        } catch(ex) {
          return done(ex);
        }
      });
    });
    req.on('error', function(err) {
      return done(err);
    });

    req.write(body);
    req.end();
  }
}
