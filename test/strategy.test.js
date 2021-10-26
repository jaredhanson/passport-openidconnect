var Strategy = require('../lib/strategy')
  , chai = require('chai')
  , uri = require('url')
  , qs = require('querystring');

describe('Strategy', function() {

  it('should redirect without redirect URI', function(done) {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345'
    }, function() {});
    
    chai.passport.use(strategy)
      .request(function(req) {
        req.session = {};
      })
      .redirect(function(url) {
        var l = uri.parse(url, true);
        
        expect(url).to.equal('https://server.example.com/authorize?response_type=code&client_id=s6BhdRkqt3&scope=openid&state=' + encodeURIComponent(l.query.state));
        // TODO: Clean this up
        expect(this.session['openidconnect:server.example.com'].state.handle).to.have.length(24);
        expect(this.session['openidconnect:server.example.com'].state.handle).to.equal(l.query.state);
        expect(this.session['openidconnect:server.example.com'].state.authorizationURL).to.equal('https://server.example.com/authorize');
        expect(this.session['openidconnect:server.example.com'].state.tokenURL).to.equal('https://server.example.com/token');
        expect(this.session['openidconnect:server.example.com'].state.clientID).to.equal('s6BhdRkqt3');
        expect(this.session['openidconnect:server.example.com'].state.clientSecret).to.equal('some_secret12345');
        expect(this.session['openidconnect:server.example.com'].state.params.response_type).to.equal('code');
        done();
      })
      .error(done)
      .authenticate();
  }); // should redirect without redirect URI
  
  it('should redirect with redirect URI', function(done) {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345',
      callbackURL: 'https://client.example.org/cb',
    }, function() {});
    
    chai.passport.use(strategy)
      .request(function(req) {
        req.session = {};
      })
      .redirect(function(url) {
        var l = uri.parse(url, true);
        
        expect(url).to.equal('https://server.example.com/authorize?response_type=code&client_id=s6BhdRkqt3&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb&scope=openid&state=' + encodeURIComponent(l.query.state));
        // TODO: Clean this up
        expect(this.session['openidconnect:server.example.com'].state.handle).to.have.length(24);
        expect(this.session['openidconnect:server.example.com'].state.handle).to.equal(l.query.state);
        expect(this.session['openidconnect:server.example.com'].state.authorizationURL).to.equal('https://server.example.com/authorize');
        expect(this.session['openidconnect:server.example.com'].state.tokenURL).to.equal('https://server.example.com/token');
        expect(this.session['openidconnect:server.example.com'].state.clientID).to.equal('s6BhdRkqt3');
        expect(this.session['openidconnect:server.example.com'].state.clientSecret).to.equal('some_secret12345');
        expect(this.session['openidconnect:server.example.com'].state.params.response_type).to.equal('code');
        done();
      })
      .error(done)
      .authenticate();
  }); // should redirect with redirect URI
  
  it('should redirect with relative redirect URI', function(done) {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345',
      callbackURL: '/cb'
    }, function() {});

    chai.passport.use(strategy)
      .request(function(req) {
        req.url = '/login';
        req.headers['host'] = 'client.example.org';
        req.session = {};
        req.connection = { encrypted: true };
      })
      .redirect(function(url) {
        var l = uri.parse(url, true);
        
        expect(url).to.equal('https://server.example.com/authorize?response_type=code&client_id=s6BhdRkqt3&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb&scope=openid&state=' + encodeURIComponent(l.query.state));
        // TODO: Clean this up
        expect(this.session['openidconnect:server.example.com'].state.handle).to.have.length(24);
        expect(this.session['openidconnect:server.example.com'].state.handle).to.equal(l.query.state);
        expect(this.session['openidconnect:server.example.com'].state.authorizationURL).to.equal('https://server.example.com/authorize');
        expect(this.session['openidconnect:server.example.com'].state.tokenURL).to.equal('https://server.example.com/token');
        expect(this.session['openidconnect:server.example.com'].state.clientID).to.equal('s6BhdRkqt3');
        expect(this.session['openidconnect:server.example.com'].state.clientSecret).to.equal('some_secret12345');
        expect(this.session['openidconnect:server.example.com'].state.params.response_type).to.equal('code');
        done();
      })
      .error(done)
      .authenticate();
  }); // should redirect with relative redirect URI
  
  it('should redirect with scope as string', function(done) {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345',
      callbackURL: 'https://client.example.org/cb',
      scope: 'profile email'
    }, function() {});
  
    chai.passport.use(strategy)
      .redirect(function(url) {
        var l = uri.parse(url, true);
        
        expect(url).to.equal('https://server.example.com/authorize?response_type=code&client_id=s6BhdRkqt3&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb&scope=openid%20profile%20email&state=' + encodeURIComponent(l.query.state));
        // TODO: Clean this up
        expect(this.session['openidconnect:server.example.com'].state.handle).to.have.length(24);
        expect(this.session['openidconnect:server.example.com'].state.handle).to.equal(l.query.state);
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
      .authenticate();
  }); // should redirect with scope as string
  
}); // Strategy
