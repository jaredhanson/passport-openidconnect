var chai = require('chai');
var sinon = require('sinon');
var Strategy = require('../lib/strategy');
var uri = require('url');
var jws = require('jws');
var AuthorizationError = require('../lib/errors/authorizationerror');
var TokenError = require('../lib/errors/tokenerror');
var InternalOAuthError = require('../lib/errors/internaloautherror');


describe('Strategy', function() {
  var clock;
  
  beforeEach(function() {
    clock = sinon.useFakeTimers(1311280970000);
  });
  
  afterEach(function() {
    clock.restore();
  });


  it('should be named openidconnect', function() {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345'
    }, function() {});
    
    expect(strategy.name).to.equal('openidconnect');
  });

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
          handle: state
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
          handle: state
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
          handle: state
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
          handle: state
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
          handle: state
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
          handle: state
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
          handle: state
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
          handle: state
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
          handle: state
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
          handle: state
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
          handle: state
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
          handle: state
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
          maxAge: 86400,
          issued: new Date('2011-07-21T20:42:50.000Z')
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
          handle: state
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
          handle: state
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
          handle: state
        });
        done();
      })
      .error(done)
      .authenticate();
  }); // should redirect with claims parameter
  
  it('should authenticate request', function(done) {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      userInfoURL: 'https://server.example.com/userinfo',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345',
      callbackURL: 'https://client.example.org/cb'
    },
    function(iss, profile, cb) {
      return cb(null, { id: '248289761001' });
    });
    
    sinon.stub(strategy._oauth2, 'getOAuthAccessToken').yieldsAsync(null, 'SlAV32hkKG', '8xLOxBtZp8', {
      token_type: 'Bearer',
      expires_in: 3600,
      id_token: jws.sign({
        header: { alg: 'HS256' },
        payload: {
          iss: 'https://server.example.com',
          sub: '248289761001',
          aud: 's6BhdRkqt3',
          exp: Math.floor((Date.now() + 1000000) / 1000),
          iat: Math.floor(Date.now() / 1000)
        },
        secret: 'keyboard cat',
      })
    });
    
    sinon.stub(strategy._oauth2, 'get').yieldsAsync(null, JSON.stringify({
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
        expect(info).to.deep.equal({});
        
        expect(strategy._oauth2.getOAuthAccessToken.calledOnce).to.be.true;
        expect(strategy._oauth2.getOAuthAccessToken.getCall(0).args[0]).to.equal('SplxlOBeZQQYbYS6WxSbIA');
        expect(strategy._oauth2.getOAuthAccessToken.getCall(0).args[1]).to.deep.equal({
          grant_type: 'authorization_code',
          redirect_uri: 'https://client.example.org/cb'
        });
        
        expect(strategy._oauth2.get.calledOnce).to.be.false;
        
        done();
      })
      .error(done)
      .authenticate();
  }); // should authenticate request
  
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
    function(iss, profile, cb) {
      return cb(null, { id: '248289761001' });
    });
    
    sinon.stub(strategy._oauth2, 'getOAuthAccessToken').yieldsAsync(null, 'SlAV32hkKG', '8xLOxBtZp8', {
      token_type: 'Bearer',
      expires_in: 3600,
      id_token: jws.sign({
        header: { alg: 'HS256' },
        payload: {
          iss: 'https://server.example.com',
          sub: '248289761001',
          aud: [ 'XXXXXXXX', 's6BhdRkqt3' ],
          azp: 's6BhdRkqt3',
          exp: Math.floor((Date.now() + 1000000) / 1000),
          iat: Math.floor(Date.now() / 1000)
        },
        secret: 'keyboard cat',
      })
    });
    
    sinon.stub(strategy._oauth2, 'get').yieldsAsync(null, JSON.stringify({
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
        expect(info).to.deep.equal({});
        done();
      })
      .error(done)
      .authenticate();
  }); // should authenticate request where audience claim contains the client ID value and authorized party claim matches client ID
  
  it('should authenticate request where time when authentication occurred is recent enough', function(done) {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      userInfoURL: 'https://server.example.com/userinfo',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345',
      callbackURL: 'https://client.example.org/cb'
    },
    function(iss, profile, cb) {
      return cb(null, { id: '248289761001' });
    });
    
    sinon.stub(strategy._oauth2, 'getOAuthAccessToken').yieldsAsync(null, 'SlAV32hkKG', '8xLOxBtZp8', {
      token_type: 'Bearer',
      expires_in: 3600,
      id_token: jws.sign({
        header: { alg: 'HS256' },
        payload: {
          iss: 'https://server.example.com',
          sub: '248289761001',
          aud: 's6BhdRkqt3',
          exp: Math.floor((Date.now() + 1000000) / 1000),
          iat: Math.floor(Date.now() / 1000), // now
          auth_time: Math.floor((Date.now() - 3600000) / 1000) // 1 hour ago
        },
        secret: 'keyboard cat',
      })
    });
    
    sinon.stub(strategy._oauth2, 'get').yieldsAsync(null, JSON.stringify({
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
            maxAge: 86400, // 1 day
            issued: new Date().toJSON() // now
          }
        };
      })
      .success(function(user, info) {
        expect(user).to.deep.equal({ id: '248289761001' });
        expect(info).to.deep.equal({});
        done();
      })
      .error(done)
      .authenticate();
  }); // should authenticate request where time when authentication occurred is recent enough
  
  it('should authenticate request with application-supplied state', function(done) {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      userInfoURL: 'https://server.example.com/userinfo',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345',
      callbackURL: 'https://client.example.org/cb'
    },
    function(iss, profile, cb) {
      return cb(null, { id: '248289761001' });
    });
    
    sinon.stub(strategy._oauth2, 'getOAuthAccessToken').yieldsAsync(null, 'SlAV32hkKG', '8xLOxBtZp8', {
      token_type: 'Bearer',
      expires_in: 3600,
      id_token: jws.sign({
        header: { alg: 'HS256' },
        payload: {
          iss: 'https://server.example.com',
          sub: '248289761001',
          aud: 's6BhdRkqt3',
          exp: Math.floor((Date.now() + 1000000) / 1000),
          iat: Math.floor(Date.now() / 1000)
        },
        secret: 'keyboard cat',
      })
    });
    
    sinon.stub(strategy._oauth2, 'get').yieldsAsync(null, JSON.stringify({
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
            state: { returnTo: 'https://client.example.org/app' }
          }
        };
      })
      .success(function(user, info) {
        expect(user).to.deep.equal({ id: '248289761001' });
        expect(info).to.deep.equal({
          state: { returnTo: 'https://client.example.org/app' }
        });
        done();
      })
      .error(done)
      .authenticate();
  }); // should authenticate request with application-supplied state
  
  it('should fail request when user denies the request', function(done) {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      userInfoURL: 'https://server.example.com/userinfo',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345',
      callbackURL: 'https://client.example.org/cb'
    },
    function(iss, profile, cb) {
      throw new Error('verify function should not be called');
    });
    
    chai.passport.use(strategy)
      .request(function(req) {
        req.query = {
          error: 'access_denied',
          error_description: 'User denied the request'
        };
      })
      .fail(function(challenge, status) {
        expect(challenge).to.deep.equal({ message: 'User denied the request' });
        expect(status).to.be.undefined;
        done();
      })
      .error(done)
      .authenticate();
  }); // should fail request when user denies the request
  
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
    function(iss, profile, cb) {
      throw new Error('verify function should not be called');
    });
    
    sinon.stub(strategy._oauth2, 'getOAuthAccessToken').yieldsAsync(null, 'SlAV32hkKG', '8xLOxBtZp8', {
      token_type: 'Bearer',
      expires_in: 3600,
      id_token: jws.sign({
        header: { alg: 'HS256' },
        payload: {
          iss: 'https://server.example.net',
          sub: '248289761001',
          aud: 's6BhdRkqt3',
          exp: Math.floor((Date.now() + 1000000) / 1000),
          iat: Math.floor(Date.now() / 1000)
        },
        secret: 'keyboard cat',
      })
    });
    
    sinon.stub(strategy._oauth2, 'get').yieldsAsync(null, JSON.stringify({
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
        expect(challenge).to.deep.equal({ message: 'ID token not issued by expected OpenID provider.' });
        expect(status).to.equal(403);
        done();
      })
      .error(done)
      .authenticate();
  }); // should forbid request when issuer claim does not match identifier of OpenID provider
  
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
    function(iss, profile, cb) {
      throw new Error('verify function should not be called');
    });
    
    sinon.stub(strategy._oauth2, 'getOAuthAccessToken').yieldsAsync(null, 'SlAV32hkKG', '8xLOxBtZp8', {
      token_type: 'Bearer',
      expires_in: 3600,
      id_token: jws.sign({
        header: { alg: 'HS256' },
        payload: {
          iss: 'https://server.example.com',
          sub: '248289761001',
          aud: [ 'XXXXXXXX', 'YYYYYYYY' ],
          exp: Math.floor((Date.now() + 1000000) / 1000),
          iat: Math.floor(Date.now() / 1000)
        },
        secret: 'keyboard cat',
      })
    });
    
    sinon.stub(strategy._oauth2, 'get').yieldsAsync(null, JSON.stringify({
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
        expect(challenge).to.deep.equal({ message: 'ID token not intended for this relying party.' });
        expect(status).to.equal(403);
        done();
      })
      .error(done)
      .authenticate();
  }); // should forbid request when audience claim does not contain the client ID value
  
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
    function(iss, profile, cb) {
      throw new Error('verify function should not be called');
    });
    
    sinon.stub(strategy._oauth2, 'getOAuthAccessToken').yieldsAsync(null, 'SlAV32hkKG', '8xLOxBtZp8', {
      token_type: 'Bearer',
      expires_in: 3600,
      id_token: jws.sign({
        header: { alg: 'HS256' },
        payload: {
          iss: 'https://server.example.com',
          sub: '248289761001',
          aud: 'XXXXXXXX',
          exp: Math.floor((Date.now() + 1000000) / 1000),
          iat: Math.floor(Date.now() / 1000)
        },
        secret: 'keyboard cat',
      })
    });
    
    sinon.stub(strategy._oauth2, 'get').yieldsAsync(null, JSON.stringify({
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
        expect(challenge).to.deep.equal({ message: 'ID token not intended for this relying party.' });
        expect(status).to.equal(403);
        done();
      })
      .error(done)
      .authenticate();
  }); // should forbid request when audience claim is a single string that does not contain the client ID value
  
  it('should forbid request when audience claim contains the client ID value but authorized party claim is not present', function(done) {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      userInfoURL: 'https://server.example.com/userinfo',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345',
      callbackURL: 'https://client.example.org/cb'
    },
    function(iss, profile, cb) {
      throw new Error('verify function should not be called');
    });
    
    sinon.stub(strategy._oauth2, 'getOAuthAccessToken').yieldsAsync(null, 'SlAV32hkKG', '8xLOxBtZp8', {
      token_type: 'Bearer',
      expires_in: 3600,
      id_token: jws.sign({
        header: { alg: 'HS256' },
        payload: {
          iss: 'https://server.example.com',
          sub: '248289761001',
          aud: [ 'XXXXXXXX', 's6BhdRkqt3' ],
          exp: Math.floor((Date.now() + 1000000) / 1000),
          iat: Math.floor(Date.now() / 1000)
        },
        secret: 'keyboard cat',
      })
    });
    
    sinon.stub(strategy._oauth2, 'get').yieldsAsync(null, JSON.stringify({
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
        expect(challenge).to.deep.equal({ message: 'ID token missing authorizied party claim.' });
        expect(status).to.equal(403);
        done();
      })
      .error(done)
      .authenticate();
  }); // should forbid request when audience claim contains the client ID value but authorized party claim is not present
  
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
    function(iss, profile, cb) {
      throw new Error('verify function should not be called');
    });
    
    sinon.stub(strategy._oauth2, 'getOAuthAccessToken').yieldsAsync(null, 'SlAV32hkKG', '8xLOxBtZp8', {
      token_type: 'Bearer',
      expires_in: 3600,
      id_token: jws.sign({
        header: { alg: 'HS256' },
        payload: {
          iss: 'https://server.example.com',
          sub: '248289761001',
          aud: [ 'XXXXXXXX', 's6BhdRkqt3' ],
          azp: 'XXXXXXXX',
          exp: Math.floor((Date.now() + 1000000) / 1000),
          iat: Math.floor(Date.now() / 1000)
        },
        secret: 'keyboard cat',
      })
    });
    
    sinon.stub(strategy._oauth2, 'get').yieldsAsync(null, JSON.stringify({
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
        expect(challenge).to.deep.equal({ message: 'ID token not issued to this relying party.' });
        expect(status).to.equal(403);
        done();
      })
      .error(done)
      .authenticate();
  }); // should forbid request when audience claim contain the client ID value but authorized party claim is not present
  
  it('should forbid request when ID token is expired', function(done) {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      userInfoURL: 'https://server.example.com/userinfo',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345',
      callbackURL: 'https://client.example.org/cb'
    },
    function(iss, profile, cb) {
      throw new Error('verify function should not be called');
    });
    
    sinon.stub(strategy._oauth2, 'getOAuthAccessToken').yieldsAsync(null, 'SlAV32hkKG', '8xLOxBtZp8', {
      token_type: 'Bearer',
      expires_in: 3600,
      id_token: jws.sign({
        header: { alg: 'HS256' },
        payload: {
          iss: 'https://server.example.com',
          sub: '248289761001',
          aud: 's6BhdRkqt3',
          exp: Math.floor((Date.now() - 60000) / 1000),
          iat: Math.floor((Date.now() - 1000000 - 60000) / 1000)
        },
        secret: 'keyboard cat',
      })
    });
    
    sinon.stub(strategy._oauth2, 'get').yieldsAsync(null, JSON.stringify({
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
        expect(challenge).to.deep.equal({ message: 'ID token has expired.' });
        expect(status).to.equal(403);
        done();
      })
      .error(done)
      .authenticate();
  }); // should forbid request when ID token is expired
  
  it('should forbid request when ID token is exactly expired', function(done) {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      userInfoURL: 'https://server.example.com/userinfo',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345',
      callbackURL: 'https://client.example.org/cb'
    },
    function(iss, profile, cb) {
      throw new Error('verify function should not be called');
    });
    
    sinon.stub(strategy._oauth2, 'getOAuthAccessToken').yieldsAsync(null, 'SlAV32hkKG', '8xLOxBtZp8', {
      token_type: 'Bearer',
      expires_in: 3600,
      id_token: jws.sign({
        header: { alg: 'HS256' },
        payload: {
          iss: 'https://server.example.com',
          sub: '248289761001',
          aud: 's6BhdRkqt3',
          exp: Math.floor(Date.now() / 1000),
          iat: Math.floor((Date.now() - 1000000) / 1000)
        },
        secret: 'keyboard cat',
      })
    });
    
    sinon.stub(strategy._oauth2, 'get').yieldsAsync(null, JSON.stringify({
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
        expect(challenge).to.deep.equal({ message: 'ID token has expired.' });
        expect(status).to.equal(403);
        done();
      })
      .error(done)
      .authenticate();
  }); // should forbid request when ID token is exactly expired
  
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
    function(iss, profile, cb) {
      throw new Error('verify function should not be called');
    });
    
    sinon.stub(strategy._oauth2, 'getOAuthAccessToken').yieldsAsync(null, 'SlAV32hkKG', '8xLOxBtZp8', {
      token_type: 'Bearer',
      expires_in: 3600,
      id_token: jws.sign({
        header: { alg: 'HS256' },
        payload: {
          iss: 'https://server.example.com',
          sub: '248289761001',
          aud: 's6BhdRkqt3',
          exp: Math.floor((Date.now() + 1000000) / 1000),
          iat: Math.floor(Date.now() / 1000)
        },
        secret: 'keyboard cat',
      })
    });
    
    sinon.stub(strategy._oauth2, 'get').yieldsAsync(null, JSON.stringify({
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
        expect(challenge).to.deep.equal({ message: 'ID token contains invalid nonce.' });
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
    function(iss, profile, cb) {
      throw new Error('verify function should not be called');
    });
    
    sinon.stub(strategy._oauth2, 'getOAuthAccessToken').yieldsAsync(null, 'SlAV32hkKG', '8xLOxBtZp8', {
      token_type: 'Bearer',
      expires_in: 3600,
      id_token: jws.sign({
        header: { alg: 'HS256' },
        payload: {
          iss: 'https://server.example.com',
          sub: '248289761001',
          aud: 's6BhdRkqt3',
          nonce: 'XXXXXXXX',
          exp: Math.floor((Date.now() + 1000000) / 1000),
          iat: Math.floor(Date.now() / 1000)
        },
        secret: 'keyboard cat',
      })
    });
    
    sinon.stub(strategy._oauth2, 'get').yieldsAsync(null, JSON.stringify({
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
        expect(challenge).to.deep.equal({ message: 'ID token contains invalid nonce.' });
        expect(status).to.equal(403);
        done();
      })
      .error(done)
      .authenticate();
  }); // should forbid request when value of nonce claim is not the same as that sent in authentication request
  
  it('should forbid request when too much time has elapsed since last authentication', function(done) {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      userInfoURL: 'https://server.example.com/userinfo',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345',
      callbackURL: 'https://client.example.org/cb'
    },
    function(iss, profile, cb) {
      throw new Error('verify function should not be called');
    });
    
    sinon.stub(strategy._oauth2, 'getOAuthAccessToken').yieldsAsync(null, 'SlAV32hkKG', '8xLOxBtZp8', {
      token_type: 'Bearer',
      expires_in: 3600,
      id_token: jws.sign({
        header: { alg: 'HS256' },
        payload: {
          iss: 'https://server.example.com',
          sub: '248289761001',
          aud: 's6BhdRkqt3',
          exp: Math.floor((Date.now() + 1000000) / 1000),
          iat: Math.floor(Date.now() / 1000), // now
          auth_time: Math.floor((Date.now() - 172800000) / 1000) // 2 days ago
        },
        secret: 'keyboard cat',
      })
    });
    
    sinon.stub(strategy._oauth2, 'get').yieldsAsync(null, JSON.stringify({
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
            maxAge: 86400, // 1 day
            issued: new Date().toJSON() // now
          }
        };
      })
      .fail(function(challenge, status) {
        expect(challenge).to.deep.equal({ message: 'Too much time has elapsed since last authentication.' });
        expect(status).to.equal(403);
        done();
      })
      .error(done)
      .authenticate();
  }); // should forbid request when too much time has elapsed since last authentication
  
  it('should error when state store yeilds an error attempting to store state', function(done) {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      userInfoURL: 'https://server.example.com/userinfo',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345',
      callbackURL: 'https://client.example.org/cb'
    },
    function(iss, profile, cb) {
      throw new Error('verify function should not be called');
    });
    
    sinon.stub(strategy._stateStore, 'store').yieldsAsync(new Error('something went wrong'));
    
    chai.passport.use(strategy)
      .request(function(req) {
        req.session = {};
      })
      .error(function(err) {
        expect(err).to.be.an.instanceof(Error);
        expect(err.message).to.equal('something went wrong');
        expect(this.session).to.deep.equal({});
        done();
      })
      .authenticate();
  }); // should error when state store yeilds an error attempting to store state
  
  it('should error when state store throws an error attempting to store state', function(done) {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      userInfoURL: 'https://server.example.com/userinfo',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345',
      callbackURL: 'https://client.example.org/cb'
    },
    function(iss, profile, cb) {
      throw new Error('verify function should not be called');
    });
    
    sinon.stub(strategy._stateStore, 'store').throws(new Error('something went wrong'));
    
    chai.passport.use(strategy)
      .request(function(req) {
        req.session = {};
      })
      .error(function(err) {
        expect(err).to.be.an.instanceof(Error);
        expect(err.message).to.equal('something went wrong');
        expect(this.session).to.deep.equal({});
        done();
      })
      .authenticate();
  }); // should error when state store throws an error attempting to store state
  
  it('should error when state store does not yield state', function(done) {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      userInfoURL: 'https://server.example.com/userinfo',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345',
      callbackURL: 'https://client.example.org/cb'
    },
    function(iss, profile, cb) {
      throw new Error('verify function should not be called');
    });
    
    sinon.stub(strategy._stateStore, 'store').yields(null);
    
    chai.passport.use(strategy)
      .request(function(req) {
        req.session = {};
      })
      .error(function(err) {
        expect(err).to.be.an.instanceof(Error);
        expect(err.message).to.equal('OpenID Connect state store did not yield state for authentication request');
        expect(this.session).to.deep.equal({});
        done();
      })
      .authenticate();
  }); // should error when state store does not yield state
  
  it('should error when receiving an authentication error response', function(done) {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      userInfoURL: 'https://server.example.com/userinfo',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345',
      callbackURL: 'https://client.example.org/cb'
    },
    function(iss, profile, cb) {
      throw new Error('verify function should not be called');
    });
    
    chai.passport.use(strategy)
      .request(function(req) {
        req.query = {
          error: 'invalid_request',
          error_description: 'Unsupported response_type value'
        };
      })
      .error(function(err) {
        expect(err).to.be.an.instanceof(AuthorizationError);
        expect(err.message).to.equal('Unsupported response_type value');
        expect(err.code).to.equal('invalid_request');
        expect(err.uri).to.be.undefined;
        expect(err.status).to.equal(500);
        done();
      })
      .authenticate();
  }); // should error when receiving an authentication error response
  
  it('should error when receiving a token error response', function(done) {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      userInfoURL: 'https://server.example.com/userinfo',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345',
      callbackURL: 'https://client.example.org/cb'
    },
    function(iss, profile, cb) {
      throw new Error('verify function should not be called');
    });
    
    sinon.stub(strategy._oauth2, 'getOAuthAccessToken').yieldsAsync({ statusCode: 400, data: '{"error":"invalid_grant","error_description":"The authorization code is invalid, expired, or revoked."}' });
    
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
      .error(function(err) {
        expect(err).to.be.an.instanceof(TokenError);
        expect(err.message).to.equal('The authorization code is invalid, expired, or revoked.');
        expect(err.code).to.equal('invalid_grant');
        expect(err.uri).to.be.undefined;
        expect(err.status).to.equal(500);
        done();
      })
      .authenticate();
  }); // should error when receiving a token error response
  
  it('should error when receiving an error with text content from token endpoint', function(done) {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      userInfoURL: 'https://server.example.com/userinfo',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345',
      callbackURL: 'https://client.example.org/cb'
    },
    function(iss, profile, cb) {
      throw new Error('verify function should not be called');
    });
    
    sinon.stub(strategy._oauth2, 'getOAuthAccessToken').yieldsAsync({ statusCode: 500, data: 'something went wrong' });
    
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
      .error(function(err) {
        expect(err).to.be.an.instanceof(InternalOAuthError);
        expect(err.message).to.equal('Failed to obtain access token');
        expect(err.oauthError).to.be.an.object;
        expect(err.oauthError.statusCode).to.equal(500);
        expect(err.oauthError.data).to.equal('something went wrong');
        done();
      })
      .authenticate();
  }); // should error when receiving an error with text content from token endpoint
  
  it('should error when receiving an internal error from token endpoint', function(done) {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      userInfoURL: 'https://server.example.com/userinfo',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345',
      callbackURL: 'https://client.example.org/cb'
    },
    function(iss, profile, cb) {
      throw new Error('verify function should not be called');
    });
    
    sinon.stub(strategy._oauth2, 'getOAuthAccessToken').yieldsAsync(new Error('something went wrong'));
    
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
      .error(function(err) {
        expect(err).to.be.an.instanceof(InternalOAuthError);
        expect(err.message).to.equal('Failed to obtain access token');
        expect(err.oauthError).to.be.an.instanceof(Error);
        expect(err.oauthError.message).to.equal('something went wrong');
        done();
      })
      .authenticate();
  }); // should error when receiving an internal error from token endpoint
  
  it('should error when token response does not include an ID token', function(done) {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      userInfoURL: 'https://server.example.com/userinfo',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345',
      callbackURL: 'https://client.example.org/cb'
    },
    function(iss, profile, cb) {
      throw new Error('verify function should not be called');
    });
    
    sinon.stub(strategy._oauth2, 'getOAuthAccessToken').yieldsAsync(null, 'SlAV32hkKG', '8xLOxBtZp8', {
      token_type: 'Bearer',
      expires_in: 3600
    });
    
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
      .error(function(err) {
        expect(err).to.be.an.instanceof(Error);
        expect(err.message).to.equal('ID token not present in token response');
        done();
      })
      .authenticate();
  }); // should error when token response does not include an ID token
  
  it('should error when ID token is missing issuer claim', function(done) {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      userInfoURL: 'https://server.example.com/userinfo',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345',
      callbackURL: 'https://client.example.org/cb'
    },
    function(iss, profile, cb) {
      throw new Error('verify function should not be called');
    });
    
    sinon.stub(strategy._oauth2, 'getOAuthAccessToken').yieldsAsync(null, 'SlAV32hkKG', '8xLOxBtZp8', {
      token_type: 'Bearer',
      expires_in: 3600,
      id_token: jws.sign({
        header: { alg: 'HS256' },
        payload: {
          sub: '248289761001',
          aud: 's6BhdRkqt3',
          exp: Math.floor((Date.now() + 1000000) / 1000),
          iat: Math.floor(Date.now() / 1000)
        },
        secret: 'keyboard cat',
      })
    });
    
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
      .error(function(err) {
        expect(err).to.be.an.instanceof(Error);
        expect(err.message).to.equal('ID token missing issuer claim');
        done();
      })
      .authenticate();
  }); // should error when ID token is missing issuer claim
  
  it('should error when ID token is missing subject claim', function(done) {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      userInfoURL: 'https://server.example.com/userinfo',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345',
      callbackURL: 'https://client.example.org/cb'
    },
    function(iss, profile, cb) {
      throw new Error('verify function should not be called');
    });
    
    sinon.stub(strategy._oauth2, 'getOAuthAccessToken').yieldsAsync(null, 'SlAV32hkKG', '8xLOxBtZp8', {
      token_type: 'Bearer',
      expires_in: 3600,
      id_token: jws.sign({
        header: { alg: 'HS256' },
        payload: {
          iss: 'https://server.example.com',
          aud: 's6BhdRkqt3',
          exp: Math.floor((Date.now() + 1000000) / 1000),
          iat: Math.floor(Date.now() / 1000)
        },
        secret: 'keyboard cat',
      })
    });
    
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
      .error(function(err) {
        expect(err).to.be.an.instanceof(Error);
        expect(err.message).to.equal('ID token missing subject claim');
        done();
      })
      .authenticate();
  }); // should error when ID token is missing subject claim
  
  it('should error when ID token is missing audience claim', function(done) {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      userInfoURL: 'https://server.example.com/userinfo',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345',
      callbackURL: 'https://client.example.org/cb'
    },
    function(iss, profile, cb) {
      throw new Error('verify function should not be called');
    });
    
    sinon.stub(strategy._oauth2, 'getOAuthAccessToken').yieldsAsync(null, 'SlAV32hkKG', '8xLOxBtZp8', {
      token_type: 'Bearer',
      expires_in: 3600,
      id_token: jws.sign({
        header: { alg: 'HS256' },
        payload: {
          iss: 'https://server.example.com',
          sub: '248289761001',
          exp: Math.floor((Date.now() + 1000000) / 1000),
          iat: Math.floor(Date.now() / 1000)
        },
        secret: 'keyboard cat',
      })
    });
    
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
      .error(function(err) {
        expect(err).to.be.an.instanceof(Error);
        expect(err.message).to.equal('ID token missing audience claim');
        done();
      })
      .authenticate();
  }); // should error when ID token is missing audience claim
  
  it('should error when ID token is missing expiration time claim', function(done) {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      userInfoURL: 'https://server.example.com/userinfo',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345',
      callbackURL: 'https://client.example.org/cb'
    },
    function(iss, profile, cb) {
      throw new Error('verify function should not be called');
    });
    
    sinon.stub(strategy._oauth2, 'getOAuthAccessToken').yieldsAsync(null, 'SlAV32hkKG', '8xLOxBtZp8', {
      token_type: 'Bearer',
      expires_in: 3600,
      id_token: jws.sign({
        header: { alg: 'HS256' },
        payload: {
          iss: 'https://server.example.com',
          sub: '248289761001',
          aud: 's6BhdRkqt3',
          iat: Math.floor(Date.now() / 1000)
        },
        secret: 'keyboard cat',
      })
    });
    
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
      .error(function(err) {
        expect(err).to.be.an.instanceof(Error);
        expect(err.message).to.equal('ID token missing expiration time claim');
        done();
      })
      .authenticate();
  }); // should error when ID token is missing expiration time claim
  
  it('should error when ID token is missing issued at claim', function(done) {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      userInfoURL: 'https://server.example.com/userinfo',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345',
      callbackURL: 'https://client.example.org/cb'
    },
    function(iss, profile, cb) {
      throw new Error('verify function should not be called');
    });
    
    sinon.stub(strategy._oauth2, 'getOAuthAccessToken').yieldsAsync(null, 'SlAV32hkKG', '8xLOxBtZp8', {
      token_type: 'Bearer',
      expires_in: 3600,
      id_token: jws.sign({
        header: { alg: 'HS256' },
        payload: {
          iss: 'https://server.example.com',
          sub: '248289761001',
          aud: 's6BhdRkqt3',
          exp: Math.floor((Date.now() + 1000000) / 1000)
        },
        secret: 'keyboard cat',
      })
    });
    
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
      .error(function(err) {
        expect(err).to.be.an.instanceof(Error);
        expect(err.message).to.equal('ID token missing issued at claim');
        done();
      })
      .authenticate();
  }); // should error when ID token is missing issued at claim
  
  it('should error when ID token audience claim is not a string or array', function(done) {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      userInfoURL: 'https://server.example.com/userinfo',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345',
      callbackURL: 'https://client.example.org/cb'
    },
    function(iss, profile, cb) {
      throw new Error('verify function should not be called');
    });
    
    sinon.stub(strategy._oauth2, 'getOAuthAccessToken').yieldsAsync(null, 'SlAV32hkKG', '8xLOxBtZp8', {
      token_type: 'Bearer',
      expires_in: 3600,
      id_token: jws.sign({
        header: { alg: 'HS256' },
        payload: {
          iss: 'https://server.example.com',
          sub: '248289761001',
          aud: 1,
          exp: Math.floor((Date.now() + 1000000) / 1000),
          iat: Math.floor(Date.now() / 1000)
        },
        secret: 'keyboard cat',
      })
    });
    
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
      .error(function(err) {
        expect(err).to.be.an.instanceof(Error);
        expect(err.message).to.equal('ID token audience claim not an array or string value');
        done();
      })
      .authenticate();
  }); // should error when ID token audience claim is not a string or array
  
  it('should error when userinfo request is unauthorized', function(done) {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      userInfoURL: 'https://server.example.com/userinfo',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345',
      callbackURL: 'https://client.example.org/cb',
      skipUserProfile: false
    },
    function(iss, profile, cb) {
      throw new Error('verify function should not be called');
    });
    
    sinon.stub(strategy._oauth2, 'getOAuthAccessToken').yieldsAsync(null, 'SlAV32hkKG', '8xLOxBtZp8', {
      token_type: 'Bearer',
      expires_in: 3600,
      id_token: jws.sign({
        header: { alg: 'HS256' },
        payload: {
          iss: 'https://server.example.com',
          sub: '248289761001',
          aud: 's6BhdRkqt3',
          exp: Math.floor((Date.now() + 1000000) / 1000),
          iat: Math.floor(Date.now() / 1000)
        },
        secret: 'keyboard cat',
      })
    });
    
    sinon.stub(strategy._oauth2, 'get').yieldsAsync({ statusCode: 401, data: '' });
    
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
      .error(function(err) {
        expect(err).to.be.an.instanceof(InternalOAuthError);
        expect(err.message).to.equal('Failed to fetch user profile');
        expect(err.oauthError).to.be.an.object;
        expect(err.oauthError.statusCode).to.equal(401);
        expect(err.oauthError.data).to.equal('');
        done();
      })
      .authenticate();
  }); // should error when userinfo request is unauthorized
  
  it('should throw if constructed without a verify function', function() {
    expect(function() {
      new Strategy();
    }).to.throw(TypeError, 'OpenIDConnectStrategy requires a verify function');
  });
  
  it('should throw if constructed without an issuer option', function() {
    expect(function() {
      new Strategy({
      }, function(){});
    }).to.throw(TypeError, 'OpenIDConnectStrategy requires an issuer option');
  });
  
  it('should throw if constructed without an authorizationURL option', function() {
    expect(function() {
      new Strategy({
        issuer: 'https://server.example.com'
      }, function(){});
    }).to.throw(TypeError, 'OpenIDConnectStrategy requires an authorizationURL option');
  });
  
  it('should throw if constructed without a tokenURL option', function() {
    expect(function() {
      new Strategy({
        issuer: 'https://server.example.com',
        authorizationURL: 'https://server.example.com/authorize'
      }, function(){});
    }).to.throw(TypeError, 'OpenIDConnectStrategy requires a tokenURL option');
  });
  
  it('should throw if constructed without a clientID option', function() {
    expect(function() {
      new Strategy({
        issuer: 'https://server.example.com',
        authorizationURL: 'https://server.example.com/authorize',
        tokenURL: 'https://server.example.com/token'
      }, function(){});
    }).to.throw(TypeError, 'OpenIDConnectStrategy requires a clientID option');
  });
  
}); // Strategy
