var OIDCStrategy = require('../lib/strategy')
  , chai = require('chai')
  , uri = require('url')
  , jwt = require('jsonwebtoken')
  , sinon = require('sinon');

describe('SessionStore', function() {
  
  function buildIdToken() {
    return jwt.sign({some: 'claim'}, 'this is a secret', {
      issuer: 'https://server.example.com',
      subject: '1234',
      audience: 's6BhdRkqt3',
      expiresIn: '1h'
    });
  };
  
  // TODO: Asser that sotre is called with correct arguments
  
    describe('#store', function() {
      var strategy = new OIDCStrategy({
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
      
    }); // #store
    
    describe('#verify', function() {
      var strategy = new OIDCStrategy({
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
      
      sinon.stub(strategy._oauth2, '_request').yieldsAsync(null, JSON.stringify({
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
                handle: 'af0ifjsldkj',
                issuer: 'https://server.example.com',
                callbackURL: 'https://www.example.net/auth/example/callback',
                params: {
                }
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
                handle: 'af0ifjsldkj',
                issuer: 'https://server.example.com',
                callbackURL: 'https://www.example.net/auth/example/callback',
                params: {
                }
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
                handle: 'af0ifjsldkj',
                issuer: 'https://server.example.com',
                callbackURL: 'https://www.example.net/auth/example/callback',
                params: {
                }
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
      
    }); // #verify
  
  
  describe('using default session state store with session key option', function() {
    var strategy = new OIDCStrategy({
      issuer: 'https://server.example.com',
      authorizationURL: 'https://www.example.com/oauth2/authorize',
      userInfoURL: 'https://www.example.com/oauth2/userinfo',
      tokenURL: 'https://www.example.com/oauth2/token',
      clientID: 's6BhdRkqt3',
      clientSecret: 'secret',
      callbackURL: 'https://www.example.net/auth/example/callback',
      state: true,
      sessionKey: 'openidconnect:example'
    },
    function(iss, sub, profile, accessToken, refreshToken, done) {
      if (iss !== 'https://server.example.com') { return done(new Error('incorrect iss argument')); }
      if (sub !== '1234') { return done(new Error('incorrect sub argument')); }
      if (typeof profile !== 'object') { return done(new Error('incorrect profile argument')); }
      if (Object.keys(profile).length === 0) { return done(new Error('incorrect profile argument')); }
      if (accessToken !== '2YotnFZFEjr1zCsicMWpAA') { return done(new Error('incorrect accessToken argument')); }
      if (refreshToken !== 'tGzv3JOkF0XG5Qx2TlKWIA') { return done(new Error('incorrect refreshToken argument')); }
      
      return done(null, { id: '1234' }, { message: 'Hello' });
    });

        strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
          if (code !== 'SplxlOBeZQQYbYS6WxSbIA') { return callback(new Error('incorrect code argument')); }
          if (options.grant_type !== 'authorization_code') { return callback(new Error('incorrect options.grant_type argument')); }
          if (options.redirect_uri !== 'https://www.example.net/auth/example/callback') { return callback(new Error('incorrect options.redirect_uri argument')); }

          return callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', {
            token_type: 'example',
            id_token: buildIdToken()
          });
        }
        strategy._oauth2._request = function(method, url, headers, post_body, access_token, callback) {
          if (method !== 'GET') { return callback(new Error('incorrect method argument')); }
          if (url !== 'https://www.example.com/oauth2/userinfo?schema=openid') { return callback(new Error('incorrect url argument')); }
          if (headers.Authorization !== 'Bearer 2YotnFZFEjr1zCsicMWpAA') { return callback(new Error('incorrect headers.Authorization argument')); }
          if (headers.Accept !== 'application/json') { return callback(new Error('incorrect headers.Accept argument')); }
          if (post_body !== null) { return callback(new Error('incorrect post_body argument')); }
          if (access_token !== null) { return callback(new Error('incorrect access_token argument')); }

          return callback(null, JSON.stringify({
            sub: '1234',
            name: 'john'
          }));
    };
    
    
    describe('issuing authorization request', function() {
      
      it('that redirects to service provider', function(done) {
          chai.passport.use(strategy)
            .request(function(req) {
              req.session = {};
            })
            .redirect(function(url) {
              var u = uri.parse(url, true);
              expect(u.query.state).to.have.length(24);
              
              expect(this.session['openidconnect:example'].state.handle).to.have.length(24);
              expect(this.session['openidconnect:example'].state.handle).to.equal(u.query.state);
              
              done();
            })
            .error(done)
            .authenticate();
      }); // that redirects to service provider
      
    }); // issuing authorization request
    
    describe('processing response to authorization request', function() {
      
      it('that was approved', function(done) {
          chai.passport.use(strategy)
            .request(function(req) {
              req.query = {};
              req.query.code = 'SplxlOBeZQQYbYS6WxSbIA';
              req.query.state = 'DkbychwKu8kBaJoLE5yeR5NK';
              req.session = {};
              req.session['openidconnect:example'] = {};
              req.session['openidconnect:example']['state'] = {
                issuer: 'https://www.example.com/',
                handle: 'DkbychwKu8kBaJoLE5yeR5NK',
                authorizationURL: 'https://www.example.com/oauth2/authorize',
                userInfoURL: 'https://www.example.com/oauth2/userinfo',
                tokenURL: 'https://www.example.com/oauth2/token',
                clientID: 'ABC123',
                clientSecret: 'secret',
                callbackURL: 'https://www.example.net/auth/example/callback',
                params: {
                  response_type: 'code',
                  client_id: 'ABC123',
                  redirect_uri: 'https://www.example.net/auth/example/callback',
                  scope: 'openid'
                }
              };
            })
            .success(function(user, info) {
              expect(user).to.be.an.object;
              expect(user.id).to.equal('1234');
              
              expect(info).to.be.an.object;
              expect(info.message).to.equal('Hello');
              
              expect(this.session['openidconnect:example']).to.be.undefined;
              
              done();
            })
            .error(done)
            .authenticate();
      }); // that was approved
      
    }); // processing response to authorization request
    
  }); // using default session state store with session key option
  
});
