exports = module.exports = function(identifier, done) {
  console.log('OpenID Discovery...');
  console.log('  identifer: ' + identifier);
}


/*
    webfinger.webfinger(identifier, 'http://openid.net/specs/connect/1.0/issuer', function(err, jrd) {
      if (err) { return self.error(err); };
      
      console.log('JRD:');
      console.log(jrd);
    });
*/
