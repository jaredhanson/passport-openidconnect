var Strategy = require('../lib/strategy'),
  chai = require('chai');


describe('Strategy', function () {
  describe('configured to work with a known OpenID provider', function () {
    describe('issuing authorization request', function () {
      describe('that redirects to service provider without redirect URI', function () {
        var strategy = new Strategy({
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret'
        },
        function (accessToken, refreshToken, profile, done) {});


        var url;

        before(function (done) {
          chai.passport.use(strategy)
            .redirect(function (u) {
              url = u;
              done();
            })
            .req(function (req) {
            })
            .authenticate();
        });

        it('should be redirected', function () {
          expect(url).to.equal('https://www.example.com/oauth2/authorize?response_type=code&client_id=ABC123&scope=openid');
        });
      }); // that redirects to service provider without redirect URI
    }); // issuing authorization request
  }); // configured to work with a known OpenID provider
});
