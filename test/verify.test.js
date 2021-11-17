var chai = require('chai');
var sinon = require('sinon');
var Strategy = require('../lib/strategy');
var jws = require('jws');


describe('verify function', function() {
  var clock;
  
  beforeEach(function() {
    clock = sinon.useFakeTimers(1311280970000);
  });
  
  afterEach(function() {
    clock.restore();
  });
  
  
  describe('that authenticates', function() {
    
    it('should accept issuer and profile to authenticate request', function(done) {
      var strategy = new Strategy({
        issuer: 'https://server.example.com',
        authorizationURL: 'https://server.example.com/authorize',
        tokenURL: 'https://server.example.com/token',
        userInfoURL: 'https://server.example.com/userinfo',
        clientID: 's6BhdRkqt3',
        clientSecret: 'some_secret12345',
        callbackURL: 'https://client.example.org/cb'
      },
      function(issuer, profile, cb) {
        expect(issuer).to.equal('https://server.example.com');
        var _raw = profile._raw; delete profile._raw;
        var _json = profile._json; delete profile._json;
        expect(profile).to.deep.equal({
          id: '248289761001',
          username: 'j.doe',
          displayName: 'Jane Doe',
          name: { familyName: 'Doe', givenName: 'Jane', middleName: undefined },
          emails: [ { value: 'janedoe@example.com' } ]
        });
        
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
          expect(strategy._oauth2.get.calledOnce).to.be.true;
          done();
        })
        .error(done)
        .authenticate();
    }); // should accept issuer and profile to authenticate request
    
    it('should accept issuer, profile, and ID token to authenticate request', function(done) {
      var strategy = new Strategy({
        issuer: 'https://server.example.com',
        authorizationURL: 'https://server.example.com/authorize',
        tokenURL: 'https://server.example.com/token',
        userInfoURL: 'https://server.example.com/userinfo',
        clientID: 's6BhdRkqt3',
        clientSecret: 'some_secret12345',
        callbackURL: 'https://client.example.org/cb'
      },
      function(issuer, profile, idToken, cb) {
        expect(issuer).to.equal('https://server.example.com');
        var _raw = profile._raw; delete profile._raw;
        var _json = profile._json; delete profile._json;
        expect(profile).to.deep.equal({
          id: '248289761001',
          username: 'j.doe',
          displayName: 'Jane Doe',
          name: { familyName: 'Doe', givenName: 'Jane', middleName: undefined },
          emails: [ { value: 'janedoe@example.com' } ]
        });
        expect(idToken).to.equal('eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL3NlcnZlci5leGFtcGxlLmNvbSIsInN1YiI6IjI0ODI4OTc2MTAwMSIsImF1ZCI6InM2QmhkUmtxdDMiLCJleHAiOjEzMTEyODE5NzAsImlhdCI6MTMxMTI4MDk3MH0.2Y-uXE7I6Gfon1v4mZVCRKIfZJ_I8BGQoedagok5MNk');
        
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
          expect(strategy._oauth2.get.calledOnce).to.be.true;
          done();
        })
        .error(done)
        .authenticate();
    }); // should accept issuer, profile, and ID token to authenticate request
    
    it('should accept issuer, profile, ID token, access token, and refresh token to authenticate request', function(done) {
      var strategy = new Strategy({
        issuer: 'https://server.example.com',
        authorizationURL: 'https://server.example.com/authorize',
        tokenURL: 'https://server.example.com/token',
        userInfoURL: 'https://server.example.com/userinfo',
        clientID: 's6BhdRkqt3',
        clientSecret: 'some_secret12345',
        callbackURL: 'https://client.example.org/cb'
      },
      function(iss, profile, idToken, accessToken, refreshToken, cb) {
        expect(iss).to.equal('https://server.example.com');
        var _raw = profile._raw; delete profile._raw;
        var _json = profile._json; delete profile._json;
        expect(profile).to.deep.equal({
          id: '248289761001',
          username: 'j.doe',
          displayName: 'Jane Doe',
          name: { familyName: 'Doe', givenName: 'Jane', middleName: undefined },
          emails: [ { value: 'janedoe@example.com' } ]
        });
        expect(idToken).to.equal('eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL3NlcnZlci5leGFtcGxlLmNvbSIsInN1YiI6IjI0ODI4OTc2MTAwMSIsImF1ZCI6InM2QmhkUmtxdDMiLCJleHAiOjEzMTEyODE5NzAsImlhdCI6MTMxMTI4MDk3MH0.2Y-uXE7I6Gfon1v4mZVCRKIfZJ_I8BGQoedagok5MNk');
        expect(accessToken).to.equal('SlAV32hkKG');
        expect(refreshToken).to.equal('8xLOxBtZp8');
        
        return cb(null, { id: '248289761001' }, { message: 'Hello' });
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
          expect(info).to.deep.equal({
            message: 'Hello'
          });
          
          expect(strategy._oauth2.getOAuthAccessToken.calledOnce).to.be.true;
          expect(strategy._oauth2.get.calledOnce).to.be.true;
          done();
        })
        .error(done)
        .authenticate();
    }); // should accept issuer, profile, ID token, access token, and refresh token to authenticate request
    
    it('should accept issuer, profile, ID token, access token, refresh token, and params to authenticate request', function(done) {
      var strategy = new Strategy({
        issuer: 'https://server.example.com',
        authorizationURL: 'https://server.example.com/authorize',
        tokenURL: 'https://server.example.com/token',
        userInfoURL: 'https://server.example.com/userinfo',
        clientID: 's6BhdRkqt3',
        clientSecret: 'some_secret12345',
        callbackURL: 'https://client.example.org/cb'
      },
      function(iss, profile, idToken, accessToken, refreshToken, params, cb) {
        expect(iss).to.equal('https://server.example.com');
        var _raw = profile._raw; delete profile._raw;
        var _json = profile._json; delete profile._json;
        expect(profile).to.deep.equal({
          id: '248289761001',
          username: 'j.doe',
          displayName: 'Jane Doe',
          name: { familyName: 'Doe', givenName: 'Jane', middleName: undefined },
          emails: [ { value: 'janedoe@example.com' } ]
        });
        expect(idToken).to.equal('eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL3NlcnZlci5leGFtcGxlLmNvbSIsInN1YiI6IjI0ODI4OTc2MTAwMSIsImF1ZCI6InM2QmhkUmtxdDMiLCJleHAiOjEzMTEyODE5NzAsImlhdCI6MTMxMTI4MDk3MH0.2Y-uXE7I6Gfon1v4mZVCRKIfZJ_I8BGQoedagok5MNk');
        expect(accessToken).to.equal('SlAV32hkKG');
        expect(refreshToken).to.equal('8xLOxBtZp8');
        expect(params).to.deep.equal({
          token_type: 'Bearer',
          expires_in: 3600,
          id_token: 'eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL3NlcnZlci5leGFtcGxlLmNvbSIsInN1YiI6IjI0ODI4OTc2MTAwMSIsImF1ZCI6InM2QmhkUmtxdDMiLCJleHAiOjEzMTEyODE5NzAsImlhdCI6MTMxMTI4MDk3MH0.2Y-uXE7I6Gfon1v4mZVCRKIfZJ_I8BGQoedagok5MNk'
        });
        
        return cb(null, { id: '248289761001' }, { message: 'Hello' });
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
          expect(info).to.deep.equal({
            message: 'Hello'
          });
          
          expect(strategy._oauth2.getOAuthAccessToken.calledOnce).to.be.true;
          expect(strategy._oauth2.get.calledOnce).to.be.true;
          done();
        })
        .error(done)
        .authenticate();
    }); // should accept issuer, profile, ID token, access token, refresh token, and params to authenticate request
    
    it('should accept request along with issuer and profile to authenticate request', function(done) {
      var strategy = new Strategy({
        issuer: 'https://server.example.com',
        authorizationURL: 'https://server.example.com/authorize',
        tokenURL: 'https://server.example.com/token',
        userInfoURL: 'https://server.example.com/userinfo',
        clientID: 's6BhdRkqt3',
        clientSecret: 'some_secret12345',
        callbackURL: 'https://client.example.org/cb',
        passReqToCallback: true
      },
      function(req, issuer, profile, cb) {
        expect(req.url).to.equal('/');
        expect(issuer).to.equal('https://server.example.com');
        var _raw = profile._raw; delete profile._raw;
        var _json = profile._json; delete profile._json;
        expect(profile).to.deep.equal({
          id: '248289761001',
          username: 'j.doe',
          displayName: 'Jane Doe',
          name: { familyName: 'Doe', givenName: 'Jane', middleName: undefined },
          emails: [ { value: 'janedoe@example.com' } ]
        });
        
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
          expect(strategy._oauth2.get.calledOnce).to.be.true;
          done();
        })
        .error(done)
        .authenticate();
    }); // should accept request along with issuer and profile to authenticate request
    
    it('should accept request along with issuer, profile, and ID token to authenticate request', function(done) {
      var strategy = new Strategy({
        issuer: 'https://server.example.com',
        authorizationURL: 'https://server.example.com/authorize',
        tokenURL: 'https://server.example.com/token',
        userInfoURL: 'https://server.example.com/userinfo',
        clientID: 's6BhdRkqt3',
        clientSecret: 'some_secret12345',
        callbackURL: 'https://client.example.org/cb',
        passReqToCallback: true
      },
      function(req, issuer, profile, idToken, cb) {
        expect(req.url).to.equal('/');
        expect(issuer).to.equal('https://server.example.com');
        var _raw = profile._raw; delete profile._raw;
        var _json = profile._json; delete profile._json;
        expect(profile).to.deep.equal({
          id: '248289761001',
          username: 'j.doe',
          displayName: 'Jane Doe',
          name: { familyName: 'Doe', givenName: 'Jane', middleName: undefined },
          emails: [ { value: 'janedoe@example.com' } ]
        });
        expect(idToken).to.equal('eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL3NlcnZlci5leGFtcGxlLmNvbSIsInN1YiI6IjI0ODI4OTc2MTAwMSIsImF1ZCI6InM2QmhkUmtxdDMiLCJleHAiOjEzMTEyODE5NzAsImlhdCI6MTMxMTI4MDk3MH0.2Y-uXE7I6Gfon1v4mZVCRKIfZJ_I8BGQoedagok5MNk');
        
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
          expect(strategy._oauth2.get.calledOnce).to.be.true;
          done();
        })
        .error(done)
        .authenticate();
    }); // should accept request along with issuer, profile, and ID token to authenticate request
    
    it('should accept request along with issuer, profile, ID token, access token, and refresh token to authenticate request', function(done) {
      var strategy = new Strategy({
        issuer: 'https://server.example.com',
        authorizationURL: 'https://server.example.com/authorize',
        tokenURL: 'https://server.example.com/token',
        userInfoURL: 'https://server.example.com/userinfo',
        clientID: 's6BhdRkqt3',
        clientSecret: 'some_secret12345',
        callbackURL: 'https://client.example.org/cb',
        passReqToCallback: true
      },
      function(req, iss, profile, idToken, accessToken, refreshToken, cb) {
        expect(req.url).to.equal('/');
        expect(iss).to.equal('https://server.example.com');
        var _raw = profile._raw; delete profile._raw;
        var _json = profile._json; delete profile._json;
        expect(profile).to.deep.equal({
          id: '248289761001',
          username: 'j.doe',
          displayName: 'Jane Doe',
          name: { familyName: 'Doe', givenName: 'Jane', middleName: undefined },
          emails: [ { value: 'janedoe@example.com' } ]
        });
        expect(idToken).to.equal('eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL3NlcnZlci5leGFtcGxlLmNvbSIsInN1YiI6IjI0ODI4OTc2MTAwMSIsImF1ZCI6InM2QmhkUmtxdDMiLCJleHAiOjEzMTEyODE5NzAsImlhdCI6MTMxMTI4MDk3MH0.2Y-uXE7I6Gfon1v4mZVCRKIfZJ_I8BGQoedagok5MNk');
        expect(accessToken).to.equal('SlAV32hkKG');
        expect(refreshToken).to.equal('8xLOxBtZp8');
        
        return cb(null, { id: '248289761001' }, { message: 'Hello' });
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
          expect(info).to.deep.equal({
            message: 'Hello'
          });
          
          expect(strategy._oauth2.getOAuthAccessToken.calledOnce).to.be.true;
          expect(strategy._oauth2.get.calledOnce).to.be.true;
          done();
        })
        .error(done)
        .authenticate();
    }); // should accept request along with issuer, profile, ID token, access token, and refresh token to authenticate request
    
    it('should accept request along with issuer, profile, ID token, access token, refresh token, and params to authenticate request', function(done) {
      var strategy = new Strategy({
        issuer: 'https://server.example.com',
        authorizationURL: 'https://server.example.com/authorize',
        tokenURL: 'https://server.example.com/token',
        userInfoURL: 'https://server.example.com/userinfo',
        clientID: 's6BhdRkqt3',
        clientSecret: 'some_secret12345',
        callbackURL: 'https://client.example.org/cb',
        passReqToCallback: true
      },
      function(req, iss, profile, idToken, accessToken, refreshToken, params, cb) {
        expect(req.url).to.equal('/');
        expect(iss).to.equal('https://server.example.com');
        var _raw = profile._raw; delete profile._raw;
        var _json = profile._json; delete profile._json;
        expect(profile).to.deep.equal({
          id: '248289761001',
          username: 'j.doe',
          displayName: 'Jane Doe',
          name: { familyName: 'Doe', givenName: 'Jane', middleName: undefined },
          emails: [ { value: 'janedoe@example.com' } ]
        });
        expect(idToken).to.equal('eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL3NlcnZlci5leGFtcGxlLmNvbSIsInN1YiI6IjI0ODI4OTc2MTAwMSIsImF1ZCI6InM2QmhkUmtxdDMiLCJleHAiOjEzMTEyODE5NzAsImlhdCI6MTMxMTI4MDk3MH0.2Y-uXE7I6Gfon1v4mZVCRKIfZJ_I8BGQoedagok5MNk');
        expect(accessToken).to.equal('SlAV32hkKG');
        expect(refreshToken).to.equal('8xLOxBtZp8');
        expect(params).to.deep.equal({
          token_type: 'Bearer',
          expires_in: 3600,
          id_token: 'eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL3NlcnZlci5leGFtcGxlLmNvbSIsInN1YiI6IjI0ODI4OTc2MTAwMSIsImF1ZCI6InM2QmhkUmtxdDMiLCJleHAiOjEzMTEyODE5NzAsImlhdCI6MTMxMTI4MDk3MH0.2Y-uXE7I6Gfon1v4mZVCRKIfZJ_I8BGQoedagok5MNk'
        });
        
        return cb(null, { id: '248289761001' }, { message: 'Hello' });
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
          expect(info).to.deep.equal({
            message: 'Hello'
          });
          
          expect(strategy._oauth2.getOAuthAccessToken.calledOnce).to.be.true;
          expect(strategy._oauth2.get.calledOnce).to.be.true;
          done();
        })
        .error(done)
        .authenticate();
    }); // should accept request along with issuer, profile, ID token, access token, refresh token, and params to authenticate request
    
    it('should accept issuer and profile to authenticate request with additional info', function(done) {
      var strategy = new Strategy({
        issuer: 'https://server.example.com',
        authorizationURL: 'https://server.example.com/authorize',
        tokenURL: 'https://server.example.com/token',
        userInfoURL: 'https://server.example.com/userinfo',
        clientID: 's6BhdRkqt3',
        clientSecret: 'some_secret12345',
        callbackURL: 'https://client.example.org/cb'
      },
      function(issuer, profile, cb) {
        expect(issuer).to.equal('https://server.example.com');
        var _raw = profile._raw; delete profile._raw;
        var _json = profile._json; delete profile._json;
        expect(profile).to.deep.equal({
          id: '248289761001',
          username: 'j.doe',
          displayName: 'Jane Doe',
          name: { familyName: 'Doe', givenName: 'Jane', middleName: undefined },
          emails: [ { value: 'janedoe@example.com' } ]
        });
        
        return cb(null, { id: '248289761001' }, { methods: [ 'password', 'otp' ] });
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
          expect(info).to.deep.equal({ methods: [ 'password', 'otp' ] });
          
          expect(strategy._oauth2.getOAuthAccessToken.calledOnce).to.be.true;
          expect(strategy._oauth2.get.calledOnce).to.be.true;
          done();
        })
        .error(done)
        .authenticate();
    }); // should accept issuer and profile to authenticate request with additional info
    
  }); // that authenticates
  
});
