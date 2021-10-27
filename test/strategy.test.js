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



      describe('that redirects to identity provider with claims option', function() {
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
            .request(function(req) {
              request = req;
              req.session = {};
            })
            .authenticate({ claims: {
              id_token: {
                email: null,
                email_verified: null
              },
              userinfo: {
                picture: null,
                email: null,
                email_verified: null
              }
            }});
        });
  
        it('should be redirected', function() {
          expect(url).to.equal('https://www.example.com/oauth2/authorize?response_type=code&client_id=ABC123&redirect_uri=https%3A%2F%2Fwww.example.net%2Flogin%2Freturn&scope=openid' + 
          '&claims=%7B%22id_token%22%3A%7B%22email%22%3Anull%2C%22email_verified%22%3Anull%7D%2C%22userinfo%22%3A%7B%22picture%22%3Anull%2C%22email%22%3Anull%2C%22email_verified%22%3Anull%7D%7D&state=' + encodeURIComponent(state));
        });
        
        it('should save state in session', function() {
          expect(request.session['openidconnect:www.example.com'].state.handle).to.have.length(24);
          expect(request.session['openidconnect:www.example.com'].state.handle).to.equal(state);

          expect(request.session['openidconnect:www.example.com'].state.authorizationURL).to.equal('https://www.example.com/oauth2/authorize');
          expect(request.session['openidconnect:www.example.com'].state.tokenURL).to.equal('https://www.example.com/oauth2/token');
          expect(request.session['openidconnect:www.example.com'].state.clientID).to.equal('ABC123');
          //expect(request.session['openidconnect:www.example.com'].state.clientSecret).to.equal('secret');
          //expect(request.session['openidconnect:www.example.com'].state.params.response_type).to.equal('code');
        });
      }); // that redirects to identity provider with claims option

      describe('that redirects to identity provider with redirect URI and claims', function() {
        var strategy = new Strategy({
          issuer: 'https://www.example.com',
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: 'https://www.example.net/login/return',
          claims: {
            id_token: {
              email: null,
              email_verified: null
            },
            userinfo: {
              picture: null,
              email: null,
              email_verified: null
            }
          }
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
            .request(function(req) {
              request = req;
              req.session = {};
            })
            .authenticate();
        });
  
        it('should be redirected', function() {
          expect(url).to.equal('https://www.example.com/oauth2/authorize?response_type=code&client_id=ABC123&redirect_uri=https%3A%2F%2Fwww.example.net%2Flogin%2Freturn&scope=openid' + 
          '&claims=%7B%22id_token%22%3A%7B%22email%22%3Anull%2C%22email_verified%22%3Anull%7D%2C%22userinfo%22%3A%7B%22picture%22%3Anull%2C%22email%22%3Anull%2C%22email_verified%22%3Anull%7D%7D&state=' + encodeURIComponent(state));
        });
        
        it('should save state in session', function() {
          expect(request.session['openidconnect:www.example.com'].state.handle).to.have.length(24);
          expect(request.session['openidconnect:www.example.com'].state.handle).to.equal(state);

          expect(request.session['openidconnect:www.example.com'].state.authorizationURL).to.equal('https://www.example.com/oauth2/authorize');
          expect(request.session['openidconnect:www.example.com'].state.tokenURL).to.equal('https://www.example.com/oauth2/token');
          expect(request.session['openidconnect:www.example.com'].state.clientID).to.equal('ABC123');
          //expect(request.session['openidconnect:www.example.com'].state.clientSecret).to.equal('secret');
          //expect(request.session['openidconnect:www.example.com'].state.params.response_type).to.equal('code');
        });
      }); // that redirects to identity provider with redirect URI and claims
  
}); // Strategy
