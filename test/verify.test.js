var chai = require('chai');
var sinon = require('sinon');
var Strategy = require('../lib/strategy');
var jwt = require('jsonwebtoken');


function buildIdToken() {
  return jwt.sign({some: 'claim'}, 'this is a secret', {
    issuer: 'https://server.example.com',
    subject: '1234',
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
      function(iss, sub, profile, accessToken, refreshToken, done) {
        if (iss !== 'https://server.example.com') { return done(new Error('incorrect iss argument')); }
        if (sub !== '1234') { return done(new Error('incorrect sub argument')); }
        if (typeof profile !== 'object') { return done(new Error('incorrect profile argument')); }
        if (Object.keys(profile).length === 0) { return done(new Error('incorrect profile argument')); }
        if (accessToken !== 'SlAV32hkKG') { return done(new Error('incorrect accessToken argument')); }
        if (refreshToken !== '8xLOxBtZp8') { return done(new Error('incorrect refreshToken argument')); }
        
        return done(null, { id: '248289761001' }, { message: 'Hello' });
      });
      
      sinon.stub(strategy._oauth2, 'getOAuthAccessToken').yieldsAsync(null, 'SlAV32hkKG', '8xLOxBtZp8', {
        token_type: 'Bearer',
        expires_in: 3600,
        id_token: buildIdToken()
      });
      
      sinon.stub(strategy._oauth2, '_request').yieldsAsync(null, JSON.stringify({
        sub: '1234',
        name: 'john'
      }));
      
      chai.passport.use(strategy)
        .request(function(req) {
          req.query = {};
          req.query = {
            code: 'SplxlOBeZQQYbYS6WxSbIA',
            state: 'af0ifjsldkj'
          };
          req.session = {};
          req.session['openidconnect:server.example.com'] = {};
          req.session['openidconnect:server.example.com']['state'] = {
            issuer: 'https://www.example.com/',
            handle: 'af0ifjsldkj',
            callbackURL: 'https://www.example.net/auth/example/callback',
            params: {
            }
          };
        })
        .success(function(user, info) {
          expect(strategy._oauth2.getOAuthAccessToken.calledOnce).to.be.true;
          expect(strategy._oauth2.getOAuthAccessToken.getCall(0).args[0]).to.equal('SplxlOBeZQQYbYS6WxSbIA');
          expect(strategy._oauth2.getOAuthAccessToken.getCall(0).args[1]).to.deep.equal({
            grant_type: 'authorization_code',
            redirect_uri: 'https://www.example.net/auth/example/callback'
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
          
          
          expect(user).to.deep.equal({ id: '248289761001' });
          
          expect(info).to.be.an.object;
          expect(info.message).to.equal('Hello');
          
          expect(this.session['openidconnect:server.example.com']).to.be.undefined;
          
          done();
        })
        .error(done)
        .authenticate();
    }); // should authenticate request
    
  }); // that authenticates
  
});
