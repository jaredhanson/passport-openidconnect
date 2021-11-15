var chai = require('chai');
var sinon = require('sinon');
var Strategy = require('../lib/strategy');
var uri = require('url');
var jwt = require('jsonwebtoken');

function buildIdToken(claims, issuer, audience) {
  issuer = issuer || 'https://server.example.com';
  audience = audience || 's6BhdRkqt3';
  
  return jwt.sign(claims, 'this is a secret', {
    issuer: issuer,
    subject: '248289761001',
    audience: audience,
    expiresIn: '1h'
  });
};


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
          issuer: 'https://server.example.com'
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
          issuer: 'https://server.example.com'
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
          issuer: 'https://server.example.com'
        });
        done();
      })
      .error(done)
      .authenticate();
  }); // should redirect with relative redirect URI
  
  it('should redirect with scope as array', function(done) {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345',
      callbackURL: 'https://client.example.org/cb',
      scope: [ 'profile', 'email' ]
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
          issuer: 'https://server.example.com'
        });
        done();
      })
      .error(done)
      .authenticate();
  }); // should redirect with scope as array
  
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
          issuer: 'https://server.example.com'
        });
        done();
      })
      .error(done)
      .authenticate();
  }); // should redirect with scope as string
  
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
          issuer: 'https://server.example.com'
        });
        done();
      })
      .error(done)
      .authenticate();
  }); // should redirect with response mode parameter
  
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
          issuer: 'https://server.example.com'
        });
        done();
      })
      .error(done)
      .authenticate();
  }); // should redirect with prompt parameter
  
  it('should redirect with prompt parameter set to extension value', function(done) {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345',
      callbackURL: 'https://client.example.org/cb',
      prompt: 'x-example'
    }, function() {});
  
    chai.passport.use(strategy)
      .request(function(req) {
        req.session = {};
      })
      .redirect(function(url) {
        var l = uri.parse(url, true);
        var state = l.query.state;
        
        expect(url).to.equal('https://server.example.com/authorize?response_type=code&client_id=s6BhdRkqt3&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb&scope=openid&prompt=x-example&state=' + encodeURIComponent(state));
        expect(state).to.have.length(24);
        expect(this.session['openidconnect:server.example.com'].state).to.deep.equal({
          handle: state,
          issuer: 'https://server.example.com'
        });
        done();
      })
      .error(done)
      .authenticate();
  }); // should redirect with prompt parameter set to extension value
  
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
          issuer: 'https://server.example.com'
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
          issuer: 'https://server.example.com'
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
          issuer: 'https://server.example.com'
        });
        done();
      })
      .error(done)
      .authenticate();
  }); // should redirect with UI locales parameter
  
  it('should redirect with login hint parameter', function(done) {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345',
      callbackURL: 'https://client.example.org/cb',
      loginHint: 'janedoe@example.com'
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
        expect(this.session['openidconnect:server.example.com'].state).to.deep.equal({
          handle: state,
          issuer: 'https://server.example.com'
        });
        done();
      })
      .error(done)
      .authenticate();
  }); // should redirect with login hint parameter
  
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
          issuer: 'https://server.example.com'
        });
        done();
      })
      .error(done)
      .authenticate();
  }); // should redirect with max age parameter
  
  it('should redirect with authentication context class reference values parameter', function(done) {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345',
      callbackURL: 'https://client.example.org/cb',
      acrValues: 'urn:mace:incommon:iap:silver'
    }, function() {});
  
    chai.passport.use(strategy)
      .request(function(req) {
        req.session = {};
      })
      .redirect(function(url) {
        var l = uri.parse(url, true);
        var state = l.query.state;
        
        expect(url).to.equal('https://server.example.com/authorize?response_type=code&client_id=s6BhdRkqt3&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb&scope=openid&acr_values=urn%3Amace%3Aincommon%3Aiap%3Asilver&state=' + encodeURIComponent(state));
        expect(state).to.have.length(24);
        expect(this.session['openidconnect:server.example.com'].state).to.deep.equal({
          handle: state,
          issuer: 'https://server.example.com'
        });
        done();
      })
      .error(done)
      .authenticate();
  }); // should redirect with authentication context class reference values parameter
  
  it('should redirect with ID token hint parameter', function(done) {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345',
      callbackURL: 'https://client.example.org/cb',
      idTokenHint: 'eyJh.ewogImlzcyI6ICJo.ggW8hZ1E'
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
          issuer: 'https://server.example.com'
        });
        done();
      })
      .error(done)
      .authenticate();
  }); // should redirect with ID token hint parameter
  
  it('should redirect with nonce parameter', function(done) {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345',
      callbackURL: 'https://client.example.org/cb',
      nonce: true
    }, function() {});
  
    chai.passport.use(strategy)
      .request(function(req) {
        req.session = {};
      })
      .redirect(function(url) {
        var l = uri.parse(url, true);
        var state = l.query.state;
        var nonce = l.query.nonce;
        
        expect(url).to.equal('https://server.example.com/authorize?response_type=code&client_id=s6BhdRkqt3&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb&scope=openid&nonce=' + encodeURIComponent(nonce) + '&state=' + encodeURIComponent(state));
        expect(state).to.have.length(24);
        expect(this.session['openidconnect:server.example.com'].state).to.deep.equal({
          handle: state,
          issuer: 'https://server.example.com',
          nonce: nonce
        });
        done();
      })
      .error(done)
      .authenticate();
  }); // should redirect with nonce parameter

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
          issuer: 'https://server.example.com'
        });
        done();
      })
      .error(done)
      .authenticate();
  }); // should redirect with claims parameter
  
  it('should authenticate request where audience claim contains the client ID value and authorized party claim matches client ID', function(done) {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      userInfoURL: 'https://server.example.com/userinfo',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345',
      callbackURL: 'https://client.example.org/cb'
    },
    function(iss, sub, profile, accessToken, refreshToken, cb) {
      expect(iss).to.equal('https://server.example.com');
      expect(sub).to.equal('248289761001');
      var _raw = profile._raw; delete profile._raw;
      var _json = profile._json; delete profile._json;
      expect(profile).to.deep.equal({
        id: '248289761001',
        username: 'j.doe',
        displayName: 'Jane Doe',
        name: { familyName: 'Doe', givenName: 'Jane', middleName: undefined },
        emails: [ { value: 'janedoe@example.com' } ]
      });
      expect(accessToken).to.equal('SlAV32hkKG');
      expect(refreshToken).to.equal('8xLOxBtZp8');
      
      return cb(null, { id: '248289761001' }, { message: 'Hello' });
    });
    
    sinon.stub(strategy._oauth2, 'getOAuthAccessToken').yieldsAsync(null, 'SlAV32hkKG', '8xLOxBtZp8', {
      token_type: 'Bearer',
      expires_in: 3600,
      id_token: buildIdToken({ azp: 's6BhdRkqt3' }, undefined, [ 'XXXXXXXX', 's6BhdRkqt3' ])
    });
    
    sinon.stub(strategy._oauth2, '_request').yieldsAsync(null, JSON.stringify({
      sub: '248289761001',
      name: 'Jane Doe',
      given_name: 'Jane',
      family_name: 'Doe',
      preferred_username: 'j.doe',
      email: 'janedoe@example.com',
      picture: 'http://example.com/janedoe/me.jpg'
    }));
    
    chai.passport.use(strategy)
      .request(function(req) {
        req.query = {
          code: 'SplxlOBeZQQYbYS6WxSbIA',
          state: 'af0ifjsldkj'
        };
        req.session = {};
        req.session['openidconnect:server.example.com'] = {
          state: {
            handle: 'af0ifjsldkj'
          }
        };
      })
      .success(function(user, info) {
        expect(user).to.deep.equal({ id: '248289761001' });
        expect(info).to.deep.equal({
          message: 'Hello'
        });
        done();
      })
      .error(done)
      .authenticate();
  }); // should authenticate request where audience claim contains the client ID value and authorized party claim matches client ID
  
  it('should forbid request when issuer claim does not match identifier of OpenID provider', function(done) {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      userInfoURL: 'https://server.example.com/userinfo',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345',
      callbackURL: 'https://client.example.org/cb'
    },
    function(iss, sub, profile, accessToken, refreshToken, cb) {
      expect(iss).to.equal('https://server.example.com');
      expect(sub).to.equal('248289761001');
      var _raw = profile._raw; delete profile._raw;
      var _json = profile._json; delete profile._json;
      expect(profile).to.deep.equal({
        id: '248289761001',
        username: 'j.doe',
        displayName: 'Jane Doe',
        name: { familyName: 'Doe', givenName: 'Jane', middleName: undefined },
        emails: [ { value: 'janedoe@example.com' } ]
      });
      expect(accessToken).to.equal('SlAV32hkKG');
      expect(refreshToken).to.equal('8xLOxBtZp8');
      
      return cb(null, { id: '248289761001' }, { message: 'Hello' });
    });
    
    sinon.stub(strategy._oauth2, 'getOAuthAccessToken').yieldsAsync(null, 'SlAV32hkKG', '8xLOxBtZp8', {
      token_type: 'Bearer',
      expires_in: 3600,
      id_token: buildIdToken({}, 'https://server.example.net')
    });
    
    sinon.stub(strategy._oauth2, '_request').yieldsAsync(null, JSON.stringify({
      sub: '248289761001',
      name: 'Jane Doe',
      given_name: 'Jane',
      family_name: 'Doe',
      preferred_username: 'j.doe',
      email: 'janedoe@example.com',
      picture: 'http://example.com/janedoe/me.jpg'
    }));
    
    chai.passport.use(strategy)
      .request(function(req) {
        req.query = {
          code: 'SplxlOBeZQQYbYS6WxSbIA',
          state: 'af0ifjsldkj'
        };
        req.session = {};
        req.session['openidconnect:server.example.com'] = {
          state: {
            handle: 'af0ifjsldkj'
          }
        };
      })
      .fail(function(challenge, status) {
        expect(challenge).to.deep.equal({ message: 'id token not issued by correct OpenID provider - expected: https://server.example.com | from: https://server.example.net' });
        expect(status).to.equal(403);
        done();
      })
      .error(done)
      .authenticate();
  }); // should forbid request when issuer claim does not match identifier of OpenID provider
  
  it('should forbid request when audience claim is a single string that does not contain the client ID value', function(done) {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      userInfoURL: 'https://server.example.com/userinfo',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345',
      callbackURL: 'https://client.example.org/cb'
    },
    function(iss, sub, profile, accessToken, refreshToken, cb) {
      expect(iss).to.equal('https://server.example.com');
      expect(sub).to.equal('248289761001');
      var _raw = profile._raw; delete profile._raw;
      var _json = profile._json; delete profile._json;
      expect(profile).to.deep.equal({
        id: '248289761001',
        username: 'j.doe',
        displayName: 'Jane Doe',
        name: { familyName: 'Doe', givenName: 'Jane', middleName: undefined },
        emails: [ { value: 'janedoe@example.com' } ]
      });
      expect(accessToken).to.equal('SlAV32hkKG');
      expect(refreshToken).to.equal('8xLOxBtZp8');
      
      return cb(null, { id: '248289761001' }, { message: 'Hello' });
    });
    
    sinon.stub(strategy._oauth2, 'getOAuthAccessToken').yieldsAsync(null, 'SlAV32hkKG', '8xLOxBtZp8', {
      token_type: 'Bearer',
      expires_in: 3600,
      id_token: buildIdToken({}, undefined, 'XXXXXXXX')
    });
    
    sinon.stub(strategy._oauth2, '_request').yieldsAsync(null, JSON.stringify({
      sub: '248289761001',
      name: 'Jane Doe',
      given_name: 'Jane',
      family_name: 'Doe',
      preferred_username: 'j.doe',
      email: 'janedoe@example.com',
      picture: 'http://example.com/janedoe/me.jpg'
    }));
    
    chai.passport.use(strategy)
      .request(function(req) {
        req.query = {
          code: 'SplxlOBeZQQYbYS6WxSbIA',
          state: 'af0ifjsldkj'
        };
        req.session = {};
        req.session['openidconnect:server.example.com'] = {
          state: {
            handle: 'af0ifjsldkj'
          }
        };
      })
      .fail(function(challenge, status) {
        expect(challenge).to.deep.equal({ message: 'aud parameter does not include this client - is: XXXXXXXX | expected: s6BhdRkqt3' });
        expect(status).to.equal(403);
        done();
      })
      .error(done)
      .authenticate();
  }); // should forbid request when audience claim is a single string that does not contain the client ID value
  
  it('should forbid request when audience claim does not contain the client ID value', function(done) {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      userInfoURL: 'https://server.example.com/userinfo',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345',
      callbackURL: 'https://client.example.org/cb'
    },
    function(iss, sub, profile, accessToken, refreshToken, cb) {
      expect(iss).to.equal('https://server.example.com');
      expect(sub).to.equal('248289761001');
      var _raw = profile._raw; delete profile._raw;
      var _json = profile._json; delete profile._json;
      expect(profile).to.deep.equal({
        id: '248289761001',
        username: 'j.doe',
        displayName: 'Jane Doe',
        name: { familyName: 'Doe', givenName: 'Jane', middleName: undefined },
        emails: [ { value: 'janedoe@example.com' } ]
      });
      expect(accessToken).to.equal('SlAV32hkKG');
      expect(refreshToken).to.equal('8xLOxBtZp8');
      
      return cb(null, { id: '248289761001' }, { message: 'Hello' });
    });
    
    sinon.stub(strategy._oauth2, 'getOAuthAccessToken').yieldsAsync(null, 'SlAV32hkKG', '8xLOxBtZp8', {
      token_type: 'Bearer',
      expires_in: 3600,
      id_token: buildIdToken({}, undefined, [ 'XXXXXXXX', 'YYYYYYYY' ])
    });
    
    sinon.stub(strategy._oauth2, '_request').yieldsAsync(null, JSON.stringify({
      sub: '248289761001',
      name: 'Jane Doe',
      given_name: 'Jane',
      family_name: 'Doe',
      preferred_username: 'j.doe',
      email: 'janedoe@example.com',
      picture: 'http://example.com/janedoe/me.jpg'
    }));
    
    chai.passport.use(strategy)
      .request(function(req) {
        req.query = {
          code: 'SplxlOBeZQQYbYS6WxSbIA',
          state: 'af0ifjsldkj'
        };
        req.session = {};
        req.session['openidconnect:server.example.com'] = {
          state: {
            handle: 'af0ifjsldkj'
          }
        };
      })
      .fail(function(challenge, status) {
        expect(challenge).to.deep.equal({ message: 'aud parameter does not include this client - is: XXXXXXXX,YYYYYYYY | expected to include: s6BhdRkqt3' });
        expect(status).to.equal(403);
        done();
      })
      .error(done)
      .authenticate();
  }); // should forbid request when audience claim does not contain the client ID value
  
  it('should forbid request when audience claim contain the client ID value but authorized party claim is not present', function(done) {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      userInfoURL: 'https://server.example.com/userinfo',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345',
      callbackURL: 'https://client.example.org/cb'
    },
    function(iss, sub, profile, accessToken, refreshToken, cb) {
      expect(iss).to.equal('https://server.example.com');
      expect(sub).to.equal('248289761001');
      var _raw = profile._raw; delete profile._raw;
      var _json = profile._json; delete profile._json;
      expect(profile).to.deep.equal({
        id: '248289761001',
        username: 'j.doe',
        displayName: 'Jane Doe',
        name: { familyName: 'Doe', givenName: 'Jane', middleName: undefined },
        emails: [ { value: 'janedoe@example.com' } ]
      });
      expect(accessToken).to.equal('SlAV32hkKG');
      expect(refreshToken).to.equal('8xLOxBtZp8');
      
      return cb(null, { id: '248289761001' }, { message: 'Hello' });
    });
    
    sinon.stub(strategy._oauth2, 'getOAuthAccessToken').yieldsAsync(null, 'SlAV32hkKG', '8xLOxBtZp8', {
      token_type: 'Bearer',
      expires_in: 3600,
      id_token: buildIdToken({}, undefined, [ 'XXXXXXXX', 's6BhdRkqt3' ])
    });
    
    sinon.stub(strategy._oauth2, '_request').yieldsAsync(null, JSON.stringify({
      sub: '248289761001',
      name: 'Jane Doe',
      given_name: 'Jane',
      family_name: 'Doe',
      preferred_username: 'j.doe',
      email: 'janedoe@example.com',
      picture: 'http://example.com/janedoe/me.jpg'
    }));
    
    chai.passport.use(strategy)
      .request(function(req) {
        req.query = {
          code: 'SplxlOBeZQQYbYS6WxSbIA',
          state: 'af0ifjsldkj'
        };
        req.session = {};
        req.session['openidconnect:server.example.com'] = {
          state: {
            handle: 'af0ifjsldkj'
          }
        };
      })
      .fail(function(challenge, status) {
        expect(challenge).to.deep.equal({ message: 'azp parameter required with multiple audiences' });
        expect(status).to.equal(403);
        done();
      })
      .error(done)
      .authenticate();
  }); // should forbid request when audience claim contain the client ID value but authorized party claim is not present
  
  it('should forbid request when authorized party claim does not match client ID', function(done) {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      userInfoURL: 'https://server.example.com/userinfo',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345',
      callbackURL: 'https://client.example.org/cb'
    },
    function(iss, sub, profile, accessToken, refreshToken, cb) {
      expect(iss).to.equal('https://server.example.com');
      expect(sub).to.equal('248289761001');
      var _raw = profile._raw; delete profile._raw;
      var _json = profile._json; delete profile._json;
      expect(profile).to.deep.equal({
        id: '248289761001',
        username: 'j.doe',
        displayName: 'Jane Doe',
        name: { familyName: 'Doe', givenName: 'Jane', middleName: undefined },
        emails: [ { value: 'janedoe@example.com' } ]
      });
      expect(accessToken).to.equal('SlAV32hkKG');
      expect(refreshToken).to.equal('8xLOxBtZp8');
      
      return cb(null, { id: '248289761001' }, { message: 'Hello' });
    });
    
    sinon.stub(strategy._oauth2, 'getOAuthAccessToken').yieldsAsync(null, 'SlAV32hkKG', '8xLOxBtZp8', {
      token_type: 'Bearer',
      expires_in: 3600,
      id_token: buildIdToken({ azp: 'XXXXXXXX' }, undefined, [ 'XXXXXXXX', 's6BhdRkqt3' ])
    });
    
    sinon.stub(strategy._oauth2, '_request').yieldsAsync(null, JSON.stringify({
      sub: '248289761001',
      name: 'Jane Doe',
      given_name: 'Jane',
      family_name: 'Doe',
      preferred_username: 'j.doe',
      email: 'janedoe@example.com',
      picture: 'http://example.com/janedoe/me.jpg'
    }));
    
    chai.passport.use(strategy)
      .request(function(req) {
        req.query = {
          code: 'SplxlOBeZQQYbYS6WxSbIA',
          state: 'af0ifjsldkj'
        };
        req.session = {};
        req.session['openidconnect:server.example.com'] = {
          state: {
            handle: 'af0ifjsldkj'
          }
        };
      })
      .fail(function(challenge, status) {
        expect(challenge).to.deep.equal({ message: 'this client is not the authorized party - expected: s6BhdRkqt3 | is: XXXXXXXX' });
        expect(status).to.equal(403);
        done();
      })
      .error(done)
      .authenticate();
  }); // should forbid request when audience claim contain the client ID value but authorized party claim is not present
  
  it('should forbid request when nonce claim is not present but value was sent in authentication request', function(done) {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      userInfoURL: 'https://server.example.com/userinfo',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345',
      callbackURL: 'https://client.example.org/cb'
    },
    function(iss, sub, profile, accessToken, refreshToken, cb) {
      expect(iss).to.equal('https://server.example.com');
      expect(sub).to.equal('248289761001');
      var _raw = profile._raw; delete profile._raw;
      var _json = profile._json; delete profile._json;
      expect(profile).to.deep.equal({
        id: '248289761001',
        username: 'j.doe',
        displayName: 'Jane Doe',
        name: { familyName: 'Doe', givenName: 'Jane', middleName: undefined },
        emails: [ { value: 'janedoe@example.com' } ]
      });
      expect(accessToken).to.equal('SlAV32hkKG');
      expect(refreshToken).to.equal('8xLOxBtZp8');
      
      return cb(null, { id: '248289761001' }, { message: 'Hello' });
    });
    
    sinon.stub(strategy._oauth2, 'getOAuthAccessToken').yieldsAsync(null, 'SlAV32hkKG', '8xLOxBtZp8', {
      token_type: 'Bearer',
      expires_in: 3600,
      id_token: buildIdToken({})
    });
    
    sinon.stub(strategy._oauth2, '_request').yieldsAsync(null, JSON.stringify({
      sub: '248289761001',
      name: 'Jane Doe',
      given_name: 'Jane',
      family_name: 'Doe',
      preferred_username: 'j.doe',
      email: 'janedoe@example.com',
      picture: 'http://example.com/janedoe/me.jpg'
    }));
    
    chai.passport.use(strategy)
      .request(function(req) {
        req.query = {
          code: 'SplxlOBeZQQYbYS6WxSbIA',
          state: 'af0ifjsldkj'
        };
        req.session = {};
        req.session['openidconnect:server.example.com'] = {
          state: {
            handle: 'af0ifjsldkj',
            nonce: 'n-0S6_WzA2Mj'
          }
        };
      })
      .fail(function(challenge, status) {
        expect(challenge).to.deep.equal({ message: 'Invalid nonce in id_token' });
        expect(status).to.equal(403);
        done();
      })
      .error(done)
      .authenticate();
  }); // should forbid request when nonce claim is not present but value was sent in authentication request
  
  it('should forbid request when value of nonce claim is not the same as that sent in authentication request', function(done) {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      userInfoURL: 'https://server.example.com/userinfo',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345',
      callbackURL: 'https://client.example.org/cb'
    },
    function(iss, sub, profile, accessToken, refreshToken, cb) {
      expect(iss).to.equal('https://server.example.com');
      expect(sub).to.equal('248289761001');
      var _raw = profile._raw; delete profile._raw;
      var _json = profile._json; delete profile._json;
      expect(profile).to.deep.equal({
        id: '248289761001',
        username: 'j.doe',
        displayName: 'Jane Doe',
        name: { familyName: 'Doe', givenName: 'Jane', middleName: undefined },
        emails: [ { value: 'janedoe@example.com' } ]
      });
      expect(accessToken).to.equal('SlAV32hkKG');
      expect(refreshToken).to.equal('8xLOxBtZp8');
      
      return cb(null, { id: '248289761001' }, { message: 'Hello' });
    });
    
    sinon.stub(strategy._oauth2, 'getOAuthAccessToken').yieldsAsync(null, 'SlAV32hkKG', '8xLOxBtZp8', {
      token_type: 'Bearer',
      expires_in: 3600,
      id_token: buildIdToken({ nonce: 'XXXXXXXX' })
    });
    
    sinon.stub(strategy._oauth2, '_request').yieldsAsync(null, JSON.stringify({
      sub: '248289761001',
      name: 'Jane Doe',
      given_name: 'Jane',
      family_name: 'Doe',
      preferred_username: 'j.doe',
      email: 'janedoe@example.com',
      picture: 'http://example.com/janedoe/me.jpg'
    }));
    
    chai.passport.use(strategy)
      .request(function(req) {
        req.query = {
          code: 'SplxlOBeZQQYbYS6WxSbIA',
          state: 'af0ifjsldkj'
        };
        req.session = {};
        req.session['openidconnect:server.example.com'] = {
          state: {
            handle: 'af0ifjsldkj',
            nonce: 'n-0S6_WzA2Mj'
          }
        };
      })
      .fail(function(challenge, status) {
        expect(challenge).to.deep.equal({ message: 'Invalid nonce in id_token' });
        expect(status).to.equal(403);
        done();
      })
      .error(done)
      .authenticate();
  }); // should forbid request when value of nonce claim is not the same as that sent in authentication request
  
}); // Strategy
