var configuration = require('./configuration').configuration;

exports = module.exports = function(identifier, done) {
  console.log('OpenID Discovery...');
  console.log('  identifer: ' + identifier);
  
  exports.discovery(identifier, function(err, issuer) {
    if (err) { return done(err); }
    
    configuration(issuer, function(err, config) {
      if (err) { return done(err); };
      
      console.log('CONFIG:');
      console.log(config);
    });
  });
}


var discoverers = [];

exports.discovery = function(identifier, done) {
  if (typeof identifier === 'function') {
    return discoverers.push(identifier);
  }

  var stack = discoverers;
  (function pass(i, err, issuer) {
    // NOTE: `err` is ignored so that fallback discovery mechanisms will be
    //       attempted.
    if (err) {
      console.log('discovery attempt failed...');
      console.log(err);
    }
    // issuer was obtained, done
    if (issuer) { return done(err, issuer); }
    
    // TODO: Allow errors to proceed, to attempt other discovery mechanisms.
    var layer = stack[i];
    if (!layer) {
      return done(new Error('Failed to discover OpenID Connect provider'));
    }
    
    try {
      layer(identifier, function(e, is) { pass(i + 1, e, is); } )
    } catch (ex) {
      return done(ex);
    }
  })(0);
}

exports.credentials = function(issuer, done) {
  
}
