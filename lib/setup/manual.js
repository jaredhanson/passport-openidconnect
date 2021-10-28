exports = module.exports = function(options) {

  return function manual(identifier, cb) {
    var missing = ['issuer', 'authorizationURL', 'tokenURL', 'clientID', 'clientSecret'].filter( function(opt) { return !options[opt] } );
    if (missing.length) return cb(new Error('Manual OpenID configuration is missing required parameter(s) - ' + missing.join(', ')));

    var params = {
      issuer: options.issuer
    }
    
    return cb(null, params);
  };
};
