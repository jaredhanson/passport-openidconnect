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
        var state = l.query.state;
        
        expect(url).to.equal('https://server.example.com/authorize?response_type=code&client_id=s6BhdRkqt3&scope=openid&state=' + encodeURIComponent(state));
        expect(state).to.have.length(24);
        expect(this.session['openidconnect:server.example.com'].state).to.deep.equal({
          handle: state,
          issuer: 'https://server.example.com',
          authorizationURL: 'https://server.example.com/authorize',
          tokenURL: 'https://server.example.com/token',
          userInfoURL: undefined,
          clientID: 's6BhdRkqt3',
          callbackURL: undefined,
          customHeaders: undefined
        });
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
        var state = l.query.state;
        
        expect(url).to.equal('https://server.example.com/authorize?response_type=code&client_id=s6BhdRkqt3&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb&scope=openid&state=' + encodeURIComponent(state));
        expect(state).to.have.length(24);
        expect(this.session['openidconnect:server.example.com'].state).to.deep.equal({
          handle: state,
          issuer: 'https://server.example.com',
          authorizationURL: 'https://server.example.com/authorize',
          tokenURL: 'https://server.example.com/token',
          userInfoURL: undefined,
          clientID: 's6BhdRkqt3',
          callbackURL: 'https://client.example.org/cb',
          customHeaders: undefined
        });
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
        var state = l.query.state;
        
        expect(url).to.equal('https://server.example.com/authorize?response_type=code&client_id=s6BhdRkqt3&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb&scope=openid&state=' + encodeURIComponent(state));
        expect(state).to.have.length(24);
        expect(this.session['openidconnect:server.example.com'].state).to.deep.equal({
          handle: state,
          issuer: 'https://server.example.com',
          authorizationURL: 'https://server.example.com/authorize',
          tokenURL: 'https://server.example.com/token',
          userInfoURL: undefined,
          clientID: 's6BhdRkqt3',
          callbackURL: 'https://client.example.org/cb',
          customHeaders: undefined
        });
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
      .request(function(req) {
        req.session = {};
      })
      .redirect(function(url) {
        var l = uri.parse(url, true);
        var state = l.query.state;
        
        expect(url).to.equal('https://server.example.com/authorize?response_type=code&client_id=s6BhdRkqt3&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb&scope=openid%20profile%20email&state=' + encodeURIComponent(state));
        expect(state).to.have.length(24);
        expect(this.session['openidconnect:server.example.com'].state).to.deep.equal({
          handle: state,
          issuer: 'https://server.example.com',
          authorizationURL: 'https://server.example.com/authorize',
          tokenURL: 'https://server.example.com/token',
          userInfoURL: undefined,
          clientID: 's6BhdRkqt3',
          callbackURL: 'https://client.example.org/cb',
          customHeaders: undefined
        });
        done();
      })
      .error(done)
      .authenticate();
  }); // should redirect with scope as string
  
  it('should redirect with prompt parameter', function(done) {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345',
      callbackURL: 'https://client.example.org/cb',
      prompt: 'login'
    }, function() {});
  
    chai.passport.use(strategy)
      .request(function(req) {
        req.session = {};
      })
      .redirect(function(url) {
        var l = uri.parse(url, true);
        var state = l.query.state;
        
        expect(url).to.equal('https://server.example.com/authorize?response_type=code&client_id=s6BhdRkqt3&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb&scope=openid&prompt=login&state=' + encodeURIComponent(state));
        expect(state).to.have.length(24);
        expect(this.session['openidconnect:server.example.com'].state).to.deep.equal({
          handle: state,
          issuer: 'https://server.example.com',
          authorizationURL: 'https://server.example.com/authorize',
          tokenURL: 'https://server.example.com/token',
          userInfoURL: undefined,
          clientID: 's6BhdRkqt3',
          callbackURL: 'https://client.example.org/cb',
          customHeaders: undefined
        });
        done();
      })
      .error(done)
      .authenticate();
  }); // should redirect with prompt parameter
  
  it('should redirect with display parameter', function(done) {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345',
      callbackURL: 'https://client.example.org/cb',
      display: 'touch'
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
        expect(this.session['openidconnect:server.example.com'].state).to.deep.equal({
          handle: state,
          issuer: 'https://server.example.com',
          authorizationURL: 'https://server.example.com/authorize',
          tokenURL: 'https://server.example.com/token',
          userInfoURL: undefined,
          clientID: 's6BhdRkqt3',
          callbackURL: 'https://client.example.org/cb',
          customHeaders: undefined
        });
        done();
      })
      .error(done)
      .authenticate();
  }); // should redirect with display parameter
  
  it('should redirect with display parameter set to extension value', function(done) {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345',
      callbackURL: 'https://client.example.org/cb',
      display: 'x-example'
    }, function() {});
  
    chai.passport.use(strategy)
      .request(function(req) {
        req.session = {};
      })
      .redirect(function(url) {
        var l = uri.parse(url, true);
        var state = l.query.state;
        
        expect(url).to.equal('https://server.example.com/authorize?response_type=code&client_id=s6BhdRkqt3&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb&scope=openid&display=x-example&state=' + encodeURIComponent(state));
        expect(state).to.have.length(24);
        expect(this.session['openidconnect:server.example.com'].state).to.deep.equal({
          handle: state,
          issuer: 'https://server.example.com',
          authorizationURL: 'https://server.example.com/authorize',
          tokenURL: 'https://server.example.com/token',
          userInfoURL: undefined,
          clientID: 's6BhdRkqt3',
          callbackURL: 'https://client.example.org/cb',
          customHeaders: undefined
        });
        done();
      })
      .error(done)
      .authenticate();
  }); // should redirect with display parameter set to extension value
  
  it('should redirect with UI locales parameter', function(done) {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345',
      callbackURL: 'https://client.example.org/cb',
      uiLocales: 'fr-CA fr en'
    }, function() {});
  
    chai.passport.use(strategy)
      .request(function(req) {
        req.session = {};
      })
      .redirect(function(url) {
        var l = uri.parse(url, true);
        var state = l.query.state;
        
        expect(url).to.equal('https://server.example.com/authorize?response_type=code&client_id=s6BhdRkqt3&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb&scope=openid&ui_locales=fr-CA%20fr%20en&state=' + encodeURIComponent(state));
        expect(state).to.have.length(24);
        expect(this.session['openidconnect:server.example.com'].state).to.deep.equal({
          handle: state,
          issuer: 'https://server.example.com',
          authorizationURL: 'https://server.example.com/authorize',
          tokenURL: 'https://server.example.com/token',
          userInfoURL: undefined,
          clientID: 's6BhdRkqt3',
          callbackURL: 'https://client.example.org/cb',
          customHeaders: undefined
        });
        done();
      })
      .error(done)
      .authenticate();
  }); // should redirect with UI locales parameter
  
  it('should redirect with max age parameter', function(done) {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345',
      callbackURL: 'https://client.example.org/cb',
      maxAge: 86400
    }, function() {});
  
    chai.passport.use(strategy)
      .request(function(req) {
        req.session = {};
      })
      .redirect(function(url) {
        var l = uri.parse(url, true);
        var state = l.query.state;
        
        expect(url).to.equal('https://server.example.com/authorize?response_type=code&client_id=s6BhdRkqt3&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb&scope=openid&max_age=86400&state=' + encodeURIComponent(state));
        expect(state).to.have.length(24);
        expect(this.session['openidconnect:server.example.com'].state).to.deep.equal({
          handle: state,
          issuer: 'https://server.example.com',
          authorizationURL: 'https://server.example.com/authorize',
          tokenURL: 'https://server.example.com/token',
          userInfoURL: undefined,
          clientID: 's6BhdRkqt3',
          callbackURL: 'https://client.example.org/cb',
          customHeaders: undefined
        });
        done();
      })
      .error(done)
      .authenticate();
  }); // should redirect with max age parameter
  
  it('should redirect with ID token hint parameter', function(done) {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345',
      callbackURL: 'https://client.example.org/cb',
      id_token_hint: 'eyJh.ewogImlzcyI6ICJo.ggW8hZ1E'
    }, function() {});
  
    chai.passport.use(strategy)
      .request(function(req) {
        req.session = {};
      })
      .redirect(function(url) {
        var l = uri.parse(url, true);
        var state = l.query.state;
        
        expect(url).to.equal('https://server.example.com/authorize?response_type=code&client_id=s6BhdRkqt3&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb&scope=openid&id_token_hint=eyJh.ewogImlzcyI6ICJo.ggW8hZ1E&state=' + encodeURIComponent(state));
        expect(state).to.have.length(24);
        expect(this.session['openidconnect:server.example.com'].state).to.deep.equal({
          handle: state,
          issuer: 'https://server.example.com',
          authorizationURL: 'https://server.example.com/authorize',
          tokenURL: 'https://server.example.com/token',
          userInfoURL: undefined,
          clientID: 's6BhdRkqt3',
          callbackURL: 'https://client.example.org/cb',
          customHeaders: undefined
        });
        done();
      })
      .error(done)
      .authenticate();
  }); // should redirect with ID token hint parameter
  
  it('should redirect with login hint parameter', function(done) {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345',
      callbackURL: 'https://client.example.org/cb',
      login_hint: 'joe@example.com'
    }, function() {});
  
    chai.passport.use(strategy)
      .request(function(req) {
        req.session = {};
      })
      .redirect(function(url) {
        var l = uri.parse(url, true);
        var state = l.query.state;
        
        expect(url).to.equal('https://server.example.com/authorize?response_type=code&client_id=s6BhdRkqt3&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb&scope=openid&login_hint=joe%40example.com&state=' + encodeURIComponent(state));
        expect(state).to.have.length(24);
        expect(this.session['openidconnect:server.example.com'].state).to.deep.equal({
          handle: state,
          issuer: 'https://server.example.com',
          authorizationURL: 'https://server.example.com/authorize',
          tokenURL: 'https://server.example.com/token',
          userInfoURL: undefined,
          clientID: 's6BhdRkqt3',
          callbackURL: 'https://client.example.org/cb',
          customHeaders: undefined
        });
        done();
      })
      .error(done)
      .authenticate();
  }); // should redirect with login hint parameter
  
  it('should redirect with response mode parameter', function(done) {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345',
      callbackURL: 'https://client.example.org/cb',
      responseMode: 'form_post'
    }, function() {});
  
    chai.passport.use(strategy)
      .request(function(req) {
        req.session = {};
      })
      .redirect(function(url) {
        var l = uri.parse(url, true);
        var state = l.query.state;
        
        expect(url).to.equal('https://server.example.com/authorize?response_type=code&response_mode=form_post&client_id=s6BhdRkqt3&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb&scope=openid&state=' + encodeURIComponent(state));
        expect(state).to.have.length(24);
        expect(this.session['openidconnect:server.example.com'].state).to.deep.equal({
          handle: state,
          issuer: 'https://server.example.com',
          authorizationURL: 'https://server.example.com/authorize',
          tokenURL: 'https://server.example.com/token',
          userInfoURL: undefined,
          clientID: 's6BhdRkqt3',
          callbackURL: 'https://client.example.org/cb',
          customHeaders: undefined
        });
        done();
      })
      .error(done)
      .authenticate();
  }); // should redirect with response mode parameter

  it('should redirect with claims parameter', function(done) {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345',
      callbackURL: 'https://client.example.org/cb',
      claims: {
        userinfo: {
          email: null,
          email_verified: null
        }
      }
    }, function() {});
    
    chai.passport.use(strategy)
      .request(function(req) {
        req.session = {};
      })
      .redirect(function(url) {
        var l = uri.parse(url, true);
        var state = l.query.state;
        
        expect(url).to.equal('https://server.example.com/authorize?response_type=code&client_id=s6BhdRkqt3&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb&scope=openid&claims=%7B%22userinfo%22%3A%7B%22email%22%3Anull%2C%22email_verified%22%3Anull%7D%7D&state=' + encodeURIComponent(state));
        expect(state).to.have.length(24);
        expect(this.session['openidconnect:server.example.com'].state).to.deep.equal({
          handle: state,
          issuer: 'https://server.example.com',
          authorizationURL: 'https://server.example.com/authorize',
          tokenURL: 'https://server.example.com/token',
          userInfoURL: undefined,
          clientID: 's6BhdRkqt3',
          callbackURL: 'https://client.example.org/cb',
          customHeaders: undefined
        });
        done();
      })
      .error(done)
      .authenticate();
  }); // should redirect with claims parameter
  
}); // Strategy
