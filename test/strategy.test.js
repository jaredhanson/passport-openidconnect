var Strategy = require('../lib/strategy')
  , chai = require('chai')
  , qs = require('querystring');

describe('strategy', function() {

  describe('configured to work with a known OpenID provider', function() {

    describe('issuing authorization request', function() {

      describe('that redirects to service provider without redirect URI', function() {
        var strategy = new Strategy({
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret'
        },
        function(accessToken, refreshToken, profile, done) {});
      
      
        var state, url;
  
        before(function(done) {
          chai.passport.use(strategy)
            .redirect(function(u) {
              state = encodeURIComponent(qs.parse(u).state);
              url = u;
              done();
            })
            .req(function(req) {
              req.session = {};
            })
            .authenticate();
        });
  
        it('should be redirected', function() {
          expect(url).to.equal('https://www.example.com/oauth2/authorize?response_type=code&client_id=ABC123&scope=openid&state=' + state);
        });
      }); // that redirects to service provider without redirect URI
  
    }); // issuing authorization request
    
  }); // configured to work with a known OpenID provider
  
}); // Strategy
