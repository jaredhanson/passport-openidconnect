var Strategy = require('../lib/strategy')
  , chai = require('chai')
  , uri = require('url')
  , qs = require('querystring');

describe('strategy', function() {

  describe('configured to work with a specific OpenID provider', function() {

    describe('issuing authorization request', function() {

      describe('that redirects to identity provider without redirect URI', function() {
        var strategy = new Strategy({
          issuer: 'https://www.example.com',
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret'
        }, function() {});
      
      
        var request, url, state;
  
        before(function(done) {
          chai.passport.use(strategy)
            .redirect(function(u) {
              var pu = uri.parse(u, true);
              
              state = pu.query.state;
              url = u;
              done();
            })
            .req(function(req) {
              request = req;
              req.session = {};
            })
            .authenticate();
        });
  
        it('should be redirected', function() {
          expect(url).to.equal('https://www.example.com/oauth2/authorize?response_type=code&client_id=ABC123&scope=openid&state=' + encodeURIComponent(state));
        });
        
        it('should save state in session', function() {
          expect(request.session['openidconnect:www.example.com'].state).to.have.length(24);
          expect(request.session['openidconnect:www.example.com'].state).to.equal(state);
        });
      }); // that redirects to identity provider without redirect URI
      
      describe('that redirects to identity provider with redirect URI', function() {
        var strategy = new Strategy({
          issuer: 'https://www.example.com',
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: 'https://www.example.net/login/return',
        }, function() {});
      
      
        var request, url, state;
  
        before(function(done) {
          chai.passport.use(strategy)
            .redirect(function(u) {
              var pu = uri.parse(u, true);
              
              state = pu.query.state;
              url = u;
              done();
            })
            .req(function(req) {
              request = req;
              req.session = {};
            })
            .authenticate();
        });
  
        it('should be redirected', function() {
          expect(url).to.equal('https://www.example.com/oauth2/authorize?response_type=code&client_id=ABC123&redirect_uri=https%3A%2F%2Fwww.example.net%2Flogin%2Freturn&scope=openid&state=' + encodeURIComponent(state));
        });
        
        it('should save state in session', function() {
          expect(request.session['openidconnect:www.example.com'].state).to.have.length(24);
          expect(request.session['openidconnect:www.example.com'].state).to.equal(state);
        });
      }); // that redirects to identity provider with redirect URI
      
      describe('that redirects to identity provider with redirect URI and scope', function() {
        var strategy = new Strategy({
          issuer: 'https://www.example.com',
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: 'https://www.example.net/login/return',
          scope: 'email'
        }, function() {});
      
      
        var request, url, state;
  
        before(function(done) {
          chai.passport.use(strategy)
            .redirect(function(u) {
              var pu = uri.parse(u, true);
              
              state = pu.query.state;
              url = u;
              done();
            })
            .req(function(req) {
              request = req;
              req.session = {};
            })
            .authenticate();
        });
  
        it('should be redirected', function() {
          expect(url).to.equal('https://www.example.com/oauth2/authorize?response_type=code&client_id=ABC123&redirect_uri=https%3A%2F%2Fwww.example.net%2Flogin%2Freturn&scope=openid%20email&state=' + encodeURIComponent(state));
        });
        
        it('should save state in session', function() {
          expect(request.session['openidconnect:www.example.com'].state).to.have.length(24);
          expect(request.session['openidconnect:www.example.com'].state).to.equal(state);
        });
      }); // that redirects to identity provider with redirect URI and scope
      
      describe('that redirects to identity provider with scope option', function() {
        var strategy = new Strategy({
          issuer: 'https://www.example.com',
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: 'https://www.example.net/login/return'
        }, function() {});
      
      
        var request, url, state;
  
        before(function(done) {
          chai.passport.use(strategy)
            .redirect(function(u) {
              var pu = uri.parse(u, true);
              
              state = pu.query.state;
              url = u;
              done();
            })
            .req(function(req) {
              request = req;
              req.session = {};
            })
            .authenticate({ scope: 'email' });
        });
  
        it('should be redirected', function() {
          expect(url).to.equal('https://www.example.com/oauth2/authorize?response_type=code&client_id=ABC123&redirect_uri=https%3A%2F%2Fwww.example.net%2Flogin%2Freturn&scope=openid%20email&state=' + encodeURIComponent(state));
        });
        
        it('should save state in session', function() {
          expect(request.session['openidconnect:www.example.com'].state).to.have.length(24);
          expect(request.session['openidconnect:www.example.com'].state).to.equal(state);
        });
      }); // that redirects to identity provider with scope option
  
    }); // issuing authorization request
    
  }); // configured to work with a known OpenID provider
  
}); // Strategy
