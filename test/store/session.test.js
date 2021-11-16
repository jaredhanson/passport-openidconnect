var chai = require('chai');
var sinon = require('sinon');
var Strategy = require('../../lib/strategy');
var uri = require('url');
var jwt = require('jsonwebtoken');


describe('SessionStore', function() {
  
  function buildIdToken() {
    return jwt.sign({some: 'claim'}, 'this is a secret', {
      issuer: 'https://server.example.com',
      subject: '248289761001',
      audience: 's6BhdRkqt3',
      expiresIn: '1h'
    });
  };
  
  
  describe('#store', function() {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345',
      callbackURL: 'https://client.example.org/cb'
    },
    function(iss, sub, profile, accessToken, refreshToken, done) {
      throw new Error('verify function should not be called');
    });
    
    var spy = sinon.spy(strategy._stateStore, 'store');
    
    it('should store strategy-specific state in session', function(done) {
      chai.passport.use(strategy)
        .request(function(req) {
          req.session = {};
        })
        .redirect(function(url) {
          var l = uri.parse(url, true);
          var state = l.query.state;
          
          expect(state).to.have.length(24);
          expect(this.session['openidconnect:server.example.com']).to.deep.equal({
            state: {
              handle: state,
              issuer: 'https://server.example.com'
            }
          });
          
          expect(spy.calledOnce).to.be.true;
          expect(spy.getCall(0).args[3]).to.deep.equal({
            issuer: 'https://server.example.com',
            authorizationURL: 'https://server.example.com/authorize',
            tokenURL: 'https://server.example.com/token',
            clientID: 's6BhdRkqt3',
            callbackURL: 'https://client.example.org/cb'
          });
          
          done();
        })
        .error(done)
        .authenticate();
    }); // should store strategy-specific state in session
    
    it('should store strategy-specific state in session alongside state set manually by app', function(done) {
      chai.passport.use(strategy)
        .request(function(req) {
          req.session = {};
          req.session['openidconnect:server.example.com'] = {
            returnTo: 'https://client.example.org/welcome'
          };
        })
        .redirect(function(url) {
          var l = uri.parse(url, true);
          var state = l.query.state;
          
          expect(state).to.have.length(24);
          expect(this.session['openidconnect:server.example.com']).to.deep.equal({
            returnTo: 'https://client.example.org/welcome',
            state: {
              handle: state,
              issuer: 'https://server.example.com'
            }
          });
          done();
        })
        .error(done)
        .authenticate();
    }); // should store strategy-specific state in session alongside state set manually by app
    
    it('should error when app does not have session support', function(done) {
      chai.passport.use(strategy)
        .error(function(err) {
          expect(err).to.be.an.instanceof(Error)
          expect(err.message).to.equal('OpenID Connect authentication requires session support when using state. Did you forget to use express-session middleware?');
          done();
        })
        .authenticate();
    }); // should error when app does not have session support
    
    it('should store strategy-specific state in session under session key', function(done) {
      var strategy = new Strategy({
        issuer: 'https://server.example.com',
        authorizationURL: 'https://server.example.com/authorize',
        tokenURL: 'https://server.example.com/token',
        clientID: 's6BhdRkqt3',
        clientSecret: 'some_secret12345',
        callbackURL: 'https://client.example.org/cb',
        sessionKey: 'openidconnect:example'
      },
      function(iss, sub, profile, accessToken, refreshToken, done) {
        throw new Error('verify function should not be called');
      });
      
      chai.passport.use(strategy)
        .request(function(req) {
          req.session = {};
        })
        .redirect(function(url) {
          var l = uri.parse(url, true);
          var state = l.query.state;
          
          expect(state).to.have.length(24);
          expect(this.session['openidconnect:example']).to.deep.equal({
            state: {
              handle: state,
              issuer: 'https://server.example.com'
            }
          });
          done();
        })
        .error(done)
        .authenticate();
    }); // should store strategy-specific state in session under session key
    
  }); // #store
    
  describe('#verify', function() {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      userInfoURL: 'https://server.example.com/userinfo',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345',
      callbackURL: 'https://client.example.org/cb'
    },
    function(iss, sub, profile, accessToken, refreshToken, done) {
      return done(null, { id: '248289761001' }, { message: 'Hello' });
    });
    
    sinon.stub(strategy._oauth2, 'getOAuthAccessToken').yieldsAsync(null, 'SlAV32hkKG', '8xLOxBtZp8', {
      token_type: 'Bearer',
      expires_in: 3600,
      id_token: buildIdToken()
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
    
    it('should remove state from session when successfully verified', function(done) {
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
          expect(this.session['openidconnect:server.example.com']).to.be.undefined;
          done();
        })
        .error(done)
        .authenticate();
    }); // should remove state from session when successfully verified
    
    it('should not remove state set manually by application from session when successfully verified', function(done) {
      chai.passport.use(strategy)
        .request(function(req) {
          req.query = {
            code: 'SplxlOBeZQQYbYS6WxSbIA',
            state: 'af0ifjsldkj'
          };
          req.session = {};
          req.session['openidconnect:server.example.com'] = {
            returnTo: 'https://client.example.org/welcome',
            state: {
              handle: 'af0ifjsldkj'
            }
          };
        })
        .success(function(user, info) {
          expect(this.session['openidconnect:server.example.com']).to.deep.equal({
            returnTo: 'https://client.example.org/welcome',
          });
          done();
        })
        .error(done)
        .authenticate();
    }); // should not remove state set manually by application from session when successfully verified
    
    it('should fail if state is not bound to session', function(done) {
      chai.passport.use(strategy)
        .request(function(req) {
          req.query = {
            code: 'SplxlOBeZQQYbYS6WxSbIA',
            state: 'XXXXXXXX'
          };
          req.session = {};
          req.session['openidconnect:server.example.com'] = {};
          req.session['openidconnect:server.example.com'] = {
            state: {
              handle: 'af0ifjsldkj'
            }
          };
        })
        .fail(function(info, status) {
          expect(info).to.deep.equal({ message: 'Invalid authorization request state.' });
          expect(status).to.equal(403);
          // FIXME: Should state be preserved in this case?
          expect(this.session['openidconnect:server.example.com']).to.be.undefined;
          done();
        })
        .error(done)
        .authenticate();
    }); // should fail if state is not bound to session
    
    it('should fail if provider-specific state is not found in session', function(done) {
      chai.passport.use(strategy)
        .request(function(req) {
          req.query = {
            code: 'SplxlOBeZQQYbYS6WxSbIA',
            state: 'af0ifjsldkj'
          };
          req.session = {};
        })
        .fail(function(info, status) {
          expect(info).to.deep.equal({ message: 'Unable to verify authorization request state.' });
          expect(status).to.equal(403);
          done();
        })
        .error(done)
        .authenticate();
    }); // should fail if provider-specific state is not found in session
    
    it('should fail if provider-specific state is missing state handle', function(done) {
      chai.passport.use(strategy)
        .request(function(req) {
          req.query = {
            code: 'SplxlOBeZQQYbYS6WxSbIA',
            state: 'af0ifjsldkj'
          };
          req.session = {};
          req.session['openidconnect:server.example.com'] = {};
        })
        .fail(function(info, status) {
          expect(info).to.deep.equal({ message: 'Unable to verify authorization request state.' });
          expect(status).to.equal(403);
          expect(this.session['openidconnect:server.example.com']).to.deep.equal({});
          done();
        })
        .error(done)
        .authenticate();
    }); // should fail if provider-specific state is missing state handle
    
    it('should error when app does not have session support', function(done) {
      chai.passport.use(strategy)
        .request(function(req) {
          req.query = {
            code: 'SplxlOBeZQQYbYS6WxSbIA',
            state: 'af0ifjsldkj'
          };
        })
        .error(function(err) {
          expect(err).to.be.an.instanceof(Error)
          expect(err.message).to.equal('OpenID Connect authentication requires session support when using state. Did you forget to use express-session middleware?');
          done();
        })
        .authenticate();
    }); // should error when app does not have session support
    
    it('should remove state from session under session key when successfully verified', function(done) {
      var strategy = new Strategy({
        issuer: 'https://server.example.com',
        authorizationURL: 'https://server.example.com/authorize',
        tokenURL: 'https://server.example.com/token',
        userInfoURL: 'https://server.example.com/userinfo',
        clientID: 's6BhdRkqt3',
        clientSecret: 'some_secret12345',
        callbackURL: 'https://client.example.org/cb',
        sessionKey: 'openidconnect:example'
      },
      function(iss, sub, profile, accessToken, refreshToken, done) {
        return done(null, { id: '248289761001' }, { message: 'Hello' });
      });
    
      sinon.stub(strategy._oauth2, 'getOAuthAccessToken').yieldsAsync(null, 'SlAV32hkKG', '8xLOxBtZp8', {
        token_type: 'Bearer',
        expires_in: 3600,
        id_token: buildIdToken()
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
          req.session['openidconnect:example'] = {
            state: {
              handle: 'af0ifjsldkj'
            }
          };
        })
        .success(function(user, info) {
          expect(this.session['openidconnect:example']).to.be.undefined;
          done();
        })
        .error(done)
        .authenticate();
    }); // should remove state from session under session key when successfully verified
    
  }); // #verify
  
});
