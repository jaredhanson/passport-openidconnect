var chai = require('chai');
var sinon = require('sinon');
var Strategy = require('../lib/strategy');
var jwt = require('jsonwebtoken');


function buildIdToken() {
  return jwt.sign({some: 'claim'}, 'this is a secret', {
    issuer: 'https://server.example.com',
    subject: '248289761001',
    audience: 's6BhdRkqt3',
    expiresIn: '1h'
  });
};


describe('verify function', function() {
  
  describe('that authenticates', function() {
    
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
          expect(user).to.deep.equal({ id: '248289761001' });
          expect(info).to.deep.equal({
            message: 'Hello'
          });
          
          expect(strategy._oauth2.getOAuthAccessToken.calledOnce).to.be.true;
          expect(strategy._oauth2.getOAuthAccessToken.getCall(0).args[0]).to.equal('SplxlOBeZQQYbYS6WxSbIA');
          expect(strategy._oauth2.getOAuthAccessToken.getCall(0).args[1]).to.deep.equal({
            grant_type: 'authorization_code',
            redirect_uri: 'https://client.example.org/cb'
          });
          
          expect(strategy._oauth2._request.calledOnce).to.be.true;
          expect(strategy._oauth2._request.getCall(0).args[0]).to.equal('GET');
          expect(strategy._oauth2._request.getCall(0).args[1]).to.equal('https://server.example.com/userinfo?schema=openid');
          expect(strategy._oauth2._request.getCall(0).args[2]).to.deep.equal({
            'Authorization': 'Bearer SlAV32hkKG',
            'Accept': 'application/json'
          });
          expect(strategy._oauth2._request.getCall(0).args[3]).to.be.null;
          expect(strategy._oauth2._request.getCall(0).args[4]).to.be.null;
          
          done();
        })
        .error(done)
        .authenticate();
    }); // should authenticate request
    
  }); // that authenticates
  
});
