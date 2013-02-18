exports = module.exports = function(identifier, done) {
  console.log('OpenID Discovery...');
  console.log('  identifer: ' + identifier);
  
  exports.discover(identifier, function(err, info) {
    if (err) { return done(err); }
    
    console.log('INFO:');
    console.log(info);
  });
}

var discoverers = [];

exports.disco =
exports.discover = function(identifier, done) {
  if (typeof identifier === 'function') {
    return discoverers.push(identifier);
  }

  var stack = discoverers;
  (function pass(i, err, info) {
    // an error or info was obtained, done
    if (err || info) { return done(err, info); }
    
    // TODO: Allow errors to proceed, to attempt other discovery mechanisms.
    var layer = stack[i];
    if (!layer) {
      return done(new Error('Failed to discover OpenID Connect provider'));
    }
    
    try {
      layer(identifier, function(e, inf) { pass(i + 1, e, inf); } )
    } catch (ex) {
      return done(ex);
    }
  })(0);
}
