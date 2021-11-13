var chai = require('chai');
var Strategy = require('../lib/strategy');
var uri = require('url');


describe('Strategy', function() {
  
  describe('#authenticate', function() {
  
    it('should redirect with redirect URI', function(done) {
      var strategy = new Strategy({
        issuer: 'https://server.example.com',
        authorizationURL: 'https://server.example.com/authorize',
        tokenURL: 'https://server.example.com/token',
        clientID: 's6BhdRkqt3',
        clientSecret: 'some_secret12345',
        callbackURL: 'https://client.example.org/cb'
      }, function() {});
      
      chai.passport.use(strategy)
        .request(function(req) {
          req.session = {};
        })
        .redirect(function(url) {
          var l = uri.parse(url, true);
          var state = l.query.state;
        
          expect(url).to.equal('https://server.example.com/authorize?response_type=code&client_id=s6BhdRkqt3&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb2&scope=openid&state=' + encodeURIComponent(state));
          expect(state).to.have.length(24);
          expect(this.session['openidconnect:server.example.com']).to.deep.equal({
            state: {
              handle: state,
              issuer: 'https://server.example.com'
            }
          });
          done();
        })
        .error(done)
        .authenticate({ callbackURL: 'https://client.example.org/cb2' });
    }); // should redirect with redirect URI
  
    it('should redirect with scope as array', function(done) {
      var strategy = new Strategy({
        issuer: 'https://server.example.com',
        authorizationURL: 'https://server.example.com/authorize',
        tokenURL: 'https://server.example.com/token',
        clientID: 's6BhdRkqt3',
        clientSecret: 'some_secret12345',
        callbackURL: 'https://client.example.org/cb'
      }, function() {});
  
      chai.passport.use(strategy)
        .request(function(req) {
          req.session = {};
        })
        .redirect(function(url) {
          var l = uri.parse(url, true);
          var state = l.query.state;
        
          expect(url).to.equal('https://server.example.com/authorize?response_type=code&client_id=s6BhdRkqt3&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb&scope=openid%20profile%20email&state=' + encodeURIComponent(state));
          expect(state).to.have.length(24);
          expect(this.session['openidconnect:server.example.com']).to.deep.equal({
            state: {
              handle: state,
              issuer: 'https://server.example.com'
            }
          });
          done();
        })
        .error(done)
        .authenticate({ scope: [ 'profile', 'email' ] });
    }); // should redirect with scope as array
  
    it('should redirect with scope as string', function(done) {
      var strategy = new Strategy({
        issuer: 'https://server.example.com',
        authorizationURL: 'https://server.example.com/authorize',
        tokenURL: 'https://server.example.com/token',
        clientID: 's6BhdRkqt3',
        clientSecret: 'some_secret12345',
        callbackURL: 'https://client.example.org/cb'
      }, function() {});
    
      chai.passport.use(strategy)
        .request(function(req) {
          req.session = {};
        })
        .redirect(function(url) {
          var l = uri.parse(url, true);
          var state = l.query.state;
        
          expect(url).to.equal('https://server.example.com/authorize?response_type=code&client_id=s6BhdRkqt3&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb&scope=openid%20profile%20email&state=' + encodeURIComponent(state));
          expect(state).to.have.length(24);
          expect(this.session['openidconnect:server.example.com']).to.deep.equal({
            state: {
              handle: state,
              issuer: 'https://server.example.com'
            }
          });
          done();
        })
        .error(done)
        .authenticate({ scope: 'profile email' });
    }); // should redirect with scope as string
    
    it('should redirect with login hint parameter', function(done) {
      var strategy = new Strategy({
        issuer: 'https://server.example.com',
        authorizationURL: 'https://server.example.com/authorize',
        tokenURL: 'https://server.example.com/token',
        clientID: 's6BhdRkqt3',
        clientSecret: 'some_secret12345',
        callbackURL: 'https://client.example.org/cb'
      }, function() {});
      
      chai.passport.use(strategy)
        .request(function(req) {
          req.session = {};
        })
        .redirect(function(url) {
          var l = uri.parse(url, true);
          var state = l.query.state;
        
          expect(url).to.equal('https://server.example.com/authorize?response_type=code&client_id=s6BhdRkqt3&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb&scope=openid&login_hint=janedoe%40example.com&state=' + encodeURIComponent(state));
          expect(state).to.have.length(24);
          expect(this.session['openidconnect:server.example.com']).to.deep.equal({
            state: {
              handle: state,
              issuer: 'https://server.example.com'
            }
          });
          done();
        })
        .error(done)
        .authenticate({ loginHint: 'janedoe@example.com' });
    }); // should redirect with login hint parameter
    
    it('should redirect with display parameter', function(done) {
      var strategy = new Strategy({
        issuer: 'https://server.example.com',
        authorizationURL: 'https://server.example.com/authorize',
        tokenURL: 'https://server.example.com/token',
        clientID: 's6BhdRkqt3',
        clientSecret: 'some_secret12345',
        callbackURL: 'https://client.example.org/cb'
      }, function() {});
      
      chai.passport.use(strategy)
        .request(function(req) {
          req.session = {};
        })
        .redirect(function(url) {
          var l = uri.parse(url, true);
          var state = l.query.state;
        
          expect(url).to.equal('https://server.example.com/authorize?response_type=code&client_id=s6BhdRkqt3&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb&scope=openid&display=touch&state=' + encodeURIComponent(state));
          expect(state).to.have.length(24);
          expect(this.session['openidconnect:server.example.com']).to.deep.equal({
            state: {
              handle: state,
              issuer: 'https://server.example.com'
            }
          });
          done();
        })
        .error(done)
        .authenticate({ display: 'touch' });
    }); // should redirect with display parameter
  
  }); // #authenticate
  
}); // Strategy
