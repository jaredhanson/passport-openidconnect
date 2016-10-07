exports = module.exports = function(options) {
  
  return function manual(identifier, cb) {
    var params = {
      issuer: options.issuer,
      authorizationURL: options.authorizationURL,
      tokenURL: options.tokenURL,
      userInfoURL: options.userInfoURL,
      clientID: options.clientID,
      clientSecret: options.clientSecret,
      callbackURL: options.callbackURL
    }

    Object.keys(options).map(opt => {
      if (['nonce', 'display', 'prompt', 'max_age', 'ui_locals', 'id_token_hint', 'login_hint', 'acr_values'].indexOf(opt) !== -1) {
        params[opt] = options[opt];
      }
    });

    return cb(null, params);
  };
};
