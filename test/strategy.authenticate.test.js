var Strategy = require('../lib/strategy')
  , chai = require('chai')
  , uri = require('url')
  , qs = require('querystring');

describe('Strategy', function() {
  
  describe('#authenticate', function() {
  
    it('that redirects to identity provider with scope as array', function(done) {
      var strategy = new Strategy({
        issuer: 'https://server.example.com',
        authorizationURL: 'https://server.example.com/authorize',
        tokenURL: 'https://server.example.com/token',
        clientID: 's6BhdRkqt3',
        clientSecret: 'some_secret12345',
        callbackURL: 'https://client.example.org/cb'
      }, function() {});
  
      chai.passport.use(strategy)
        .redirect(function(url) {
          var pu = uri.parse(url, true);
        
          expect(url).to.equal('https://server.example.com/authorize?response_type=code&client_id=s6BhdRkqt3&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb&scope=openid%20profile%20email&state=' + encodeURIComponent(pu.query.state));
          // TODO: Clean this up
          expect(this.session['openidconnect:server.example.com'].state.handle).to.have.length(24);
          expect(this.session['openidconnect:server.example.com'].state.handle).to.equal(pu.query.state);
          expect(this.session['openidconnect:server.example.com'].state.authorizationURL).to.equal('https://server.example.com/authorize');
          expect(this.session['openidconnect:server.example.com'].state.tokenURL).to.equal('https://server.example.com/token');
          expect(this.session['openidconnect:server.example.com'].state.clientID).to.equal('s6BhdRkqt3');
          expect(this.session['openidconnect:server.example.com'].state.clientSecret).to.equal('some_secret12345');
          expect(this.session['openidconnect:server.example.com'].state.params.response_type).to.equal('code');
          done();
        })
        .request(function(req) {
          req.session = {};
        })
        .error(done)
        .authenticate({ scope: [ 'profile', 'email' ] });
    }); // that redirects to identity provider with scope as array
  
    it('that redirects to identity provider with scope as string', function(done) {
      var strategy = new Strategy({
        issuer: 'https://server.example.com',
        authorizationURL: 'https://server.example.com/authorize',
        tokenURL: 'https://server.example.com/token',
        clientID: 's6BhdRkqt3',
        clientSecret: 'some_secret12345',
        callbackURL: 'https://client.example.org/cb'
      }, function() {});
    
      chai.passport.use(strategy)
        .redirect(function(url) {
          var pu = uri.parse(url, true);
        
          expect(url).to.equal('https://server.example.com/authorize?response_type=code&client_id=s6BhdRkqt3&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb&scope=openid%20profile%20email&state=' + encodeURIComponent(pu.query.state));
          // TODO: Clean this up
          expect(this.session['openidconnect:server.example.com'].state.handle).to.have.length(24);
          expect(this.session['openidconnect:server.example.com'].state.handle).to.equal(pu.query.state);
          expect(this.session['openidconnect:server.example.com'].state.authorizationURL).to.equal('https://server.example.com/authorize');
          expect(this.session['openidconnect:server.example.com'].state.tokenURL).to.equal('https://server.example.com/token');
          expect(this.session['openidconnect:server.example.com'].state.clientID).to.equal('s6BhdRkqt3');
          expect(this.session['openidconnect:server.example.com'].state.clientSecret).to.equal('some_secret12345');
          expect(this.session['openidconnect:server.example.com'].state.params.response_type).to.equal('code');
          done();
        })
        .request(function(req) {
          req.session = {};
        })
        .error(done)
        .authenticate({ scope: 'profile email' });
    }); // that redirects to identity provider with scope as string
  
  }); // #authenticate
  
}); // Strategy
