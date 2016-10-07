function Registrar(options) {
  options = options || {};

  this._getClientCb = options.getClientCallback;
  if (!this._getClientCb) {
    throw new Error('OpenID Connect authentication requires getClientCallback option');
  }
}

Registrar.prototype.resolve = function(issuer, cb) {
  this._getClientCb(issuer, function(err, client) {
    if (err) { return cb(err); }
    if (!client) {
      return cb(new Error('No client able to interact with OpenID provider: ' + issuer));
    }

    if (!provider.registrationURL) {
      throw new Error('Can\'t register without registrationURL');
    }

    // https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
    var clientMetadata = this.options.clientMetadata;

    request.post(//////////////////////////////)


    return cb(null, client);
  });
}


module.exports = Registrar;
