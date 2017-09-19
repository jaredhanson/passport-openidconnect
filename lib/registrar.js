var request = require('request');

/**
 * @params function  options.getClientCallback   REQUIRED  function(issuer, cb)
 * @params function  options.saveClientCallback  OPTIONAL  function(client, cb)
 * @params object    options.clientMetadata
 *    See https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
 */
function Registrar(options) {
  this.options = options || {};

  this._getClientCb = this.options.getClientCallback;
  if (!this._getClientCb) {
    throw new Error('OpenID Connect registration requires getClientCallback option');
  }
}

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
 *   - [OpenID Connect Dynamic Client Registration 1.0](https://openid.net/specs/openid-connect-registration-1_0.html)
 *
 * @param object  config
 * @param string  config.issuer
 * @param string  config.registrationURL
 */
Registrar.prototype.resolve = function (config, cb) {
  var options = this.options;

  this._getClientCb(config.issuer, function (err, client) {
    if (err) { return cb(err); }
    if (client) { return cb(null, client); } // TODO: Validate needed client data and expiration.

    if (!config.registrationURL) {
      throw new Error('Can\'t register without registrationURL');
    }

    request.post({
      uri: config.registrationURL,
      json: options.clientMetadata
    }, function (err, res, body) {
      if (err) { return cb(err); }
      if (res.statusCode !== 201) {
        // Should this be a warning?
        // "A successful response SHOULD use the HTTP 201 Created status code"
        return cb(new Error('Unexpected status code from OpenID provider configuration: ' +
                            res.statusCode));
      }

      if (!('client_id' in body)) {
        return cb(new Error('Missing client_id in response from provider.'));
      }

      client = {
        id: body.client_id,
        _json: body
      };
      if ('client_secret' in body) {
        if (!('client_secret_expires_at' in body)) {
          // client_secret_expires_at is REQUIRED if there is a client_secret.
          return cb(new Error('Missing client_secret_expires_at in response from provider.'));
        }

        client.secret = body.client_secret;
        client.secretExpiresAt = body.client_secret_expires_at;
      }
      if ('registration_access_token' in body) {
        client.registrationAccessToken = body.registration_access_token;
      }
      if ('registration_client_uri' in body) {
        client.registrationClientURI = body.registration_client_uri;
      }
      if ('client_id_issued_at' in body) {
        client.idIssuedAt = body.client_id_issued_at;
      }

      if (typeof options.saveClientCallback === 'function') {
        return options.saveClientCallback(client, cb);
      }

      cb(null, client);
    });
  });
};


module.exports = Registrar;
