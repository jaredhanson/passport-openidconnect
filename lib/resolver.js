var webfinger = require('webfinger').webfinger;

//var REL = 'http://openid.net/specs/connect/1.0/issuer';
var REL = 'http://specs.openid.net/auth/2.0/provider';


function Resolver() {
}

Resolver.prototype.resolve = function(identifier, cb) {
  webfinger(identifier, REL, { webfingerOnly: true }, function(err, jrd) {
    if (err) { return cb(err); };
    if (!jrd.links) { return cb(new Error('No links in resource descriptor')); }
    
    var issuer;
    for (var i = 0; i < jrd.links.length; i++) {
      var link = jrd.links[i];
      if (link.rel == REL) {
        issuer = link.href;
        break;
      }
    }
    
    if (!issuer) { return cb(new Error('No OpenID Connect issuer in resource descriptor')); }
    // FIXME: Return the actual issuer.
    return cb(null, 'https://accounts.google.com/');
  });
}


module.exports = Resolver;
