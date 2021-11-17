var chai = require('chai');
var sinon = require('sinon');
var Strategy = require('../../lib/strategy');
var uri = require('url');
var jws = require('jws');


describe('SessionStore', function() {
  
  describe('#store', function() {
    var strategy = new Strategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://server.example.com/authorize',
      tokenURL: 'https://server.example.com/token',
      clientID: 's6BhdRkqt3',
      clientSecret: 'some_secret12345',
      callbackURL: 'https://client.example.org/cb'
    },
    function(iss, profile, done) {
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
              handle: state
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
            returnTo: 'https://client.example.org/app'
          };
        })
        .redirect(function(url) {
          var l = uri.parse(url, true);
          var state = l.query.state;
          
          expect(state).to.have.length(24);
          expect(this.session['openidconnect:server.example.com']).to.deep.equal({
            returnTo: 'https://client.example.org/app',
            state: {
              handle: state
            }
          });
          done();
        })
        .error(done)
        .authenticate();
    }); // should store strategy-specific state in session alongside state set manually by app
    
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
      function(iss, profile, done) {
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
              handle: state
            }
          });
          done();
        })
        .error(done)
        .authenticate();
    }); // should store strategy-specific state in session under session key
    
    it('should error when app does not have session support', function(done) {
      chai.passport.use(strategy)
        .error(function(err) {
          expect(err).to.be.an.instanceof(Error)
          expect(err.message).to.equal('OpenID Connect requires session support. Did you forget to use `express-session` middleware?');
          done();
        })
        .authenticate();
    }); // should error when app does not have session support
    
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
    function(iss, profile, done) {
      return done(null, { id: '248289761001' });
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
            returnTo: 'https://client.example.org/app',
            state: {
              handle: 'af0ifjsldkj'
            }
          };
        })
        .success(function(user, info) {
          expect(this.session['openidconnect:server.example.com']).to.deep.equal({
            returnTo: 'https://client.example.org/app',
          });
          done();
        })
        .error(done)
        .authenticate();
    }); // should not remove state set manually by application from session when successfully verified
    
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
      function(iss, profile, done) {
        return done(null, { id: '248289761001' }, { message: 'Hello' });
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
    
    it('should fail if provider-specific state is not available in session', function(done) {
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
    }); // should fail if provider-specific state is not available in session
    
    it('should fail if provider-specific state is missing state', function(done) {
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
    }); // should fail if provider-specific state is missing state
    
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
          expect(err.message).to.equal('OpenID Connect requires session support. Did you forget to use `express-session` middleware?');
          done();
        })
        .authenticate();
    }); // should error when app does not have session support
    
  }); // #verify
  
});
