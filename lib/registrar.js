var request = require('request');

/**
 * @params function  options.getClientCallback
 * @params object    options.clientMetadata
 *    See https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
 */
function Registrar(options) {
  this.options = options || {};

  this._getClientCb = this.options.getClientCallback;
  if (!this._getClientCb) {
    throw new Error('OpenID Connect authentication requires getClientCallback option');
  }
}

/**
 * @param object  config
 * @param string  config.issuer
 * @param string  config.registrationURL
 */
Registrar.prototype.resolve = function (config, cb) {
  var options = this.options;

  this._getClientCb(config.issuer, function (err, client) {
    if (err) { return cb(err); }
    if (client) { return cb(null, client); }

    if (!config.registrationURL) {
      throw new Error('Can\'t register without registrationURL');
    }


    request.post({
      uri: config.registrationURL,
      json: options.clientMetadata
    }, function (err, res, body) {
      if (err) { return cb(err); }
      if (res.statusCode !== 201) {
        return cb(new Error('Unexpected status code from OpenID provider configuration: ' +
                            res.statusCode));
      }

      // TODO: Validate response data.
      client = {
        id: body.client_id,
        _raw: body
      };
      if ('client_secret' in body) {
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

      cb(null, client);
    });
  });
};


module.exports = Registrar;
