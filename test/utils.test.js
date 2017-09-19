var utils = require('../lib/utils');

describe('utils', function() {
  describe('originalUrl', function() {
    it("can determine https from the connection encryption status", function() {
      var req = createVanillaRequest();

      expect(utils.originalURL(req)).to.equal('http://google.com/woot');

      req.connection.encrypted = true;

      expect(utils.originalURL(req)).to.equal('https://google.com/woot');
    });

    describe("can determine the host from the x-forwarded-host header", function() {
      it("with no options", function() {
        var req = createVanillaRequest();

        req.headers['x-forwarded-host'] = 'yahoo.com';

        expect(utils.originalURL(req)).to.equal('http://google.com/woot');
      });

      it("with the proxy option", function() {
        var req = createVanillaRequest();

        req.headers['x-forwarded-host'] = 'yahoo.com';

        expect(utils.originalURL(req, { })).to.equal('http://google.com/woot');
        expect(utils.originalURL(req, { proxy : false })).to.equal('http://google.com/woot');
        expect(utils.originalURL(req, { proxy : null })).to.equal('http://google.com/woot');
        expect(utils.originalURL(req, { proxy : true })).to.equal('http://yahoo.com/woot');
      });

      it("with an app object on the request", function() {
        var req = createVanillaRequest();

        req.app = {
          get : function(name) {
            if (name === 'trust proxy') {
              return false;
            }
          }
        };

        req.headers['x-forwarded-host'] = 'yahoo.com';

        expect(utils.originalURL(req)).to.equal('http://google.com/woot');
        expect(utils.originalURL(req, { })).to.equal('http://google.com/woot');
        expect(utils.originalURL(req, { proxy : false })).to.equal('http://google.com/woot');

        req.app = {
          get : function(name) {
            if (name === 'trust proxy') {
              return true;
            }
          }
        };

        expect(utils.originalURL(req)).to.equal('http://yahoo.com/woot');
        expect(utils.originalURL(req), { }).to.equal('http://yahoo.com/woot');
        expect(utils.originalURL(req), { proxy : false }).to.equal('http://yahoo.com/woot');
        expect(utils.originalURL(req), { proxy : true }).to.equal('http://yahoo.com/woot');
      });
    });

    describe("can determine the protocol from the x-forwarded-proto header", function() {
      it("with no options", function() {
        var req = createVanillaRequest();

        req.headers['x-forwarded-proto'] = 'http';

        expect(utils.originalURL(req)).to.equal('http://google.com/woot');

        req.headers['x-forwarded-proto'] = 'https';

        expect(utils.originalURL(req)).to.equal('http://google.com/woot');
      });

      it("with the proxy option", function() {
        var req = createVanillaRequest();

        req.headers['x-forwarded-proto'] = 'https';

        expect(utils.originalURL(req, { })).to.equal('http://google.com/woot');
        expect(utils.originalURL(req, { proxy : false })).to.equal('http://google.com/woot');
        expect(utils.originalURL(req, { proxy : null })).to.equal('http://google.com/woot');
        expect(utils.originalURL(req, { proxy : true })).to.equal('https://google.com/woot');
      });

      it("with an app object on the request", function() {
        var req = createVanillaRequest();

        req.app = {
          get : function(name) {
            if (name === 'trust proxy') {
              return false;
            }
          }
        };

        req.headers['x-forwarded-proto'] = 'https';

        expect(utils.originalURL(req)).to.equal('http://google.com/woot');
        expect(utils.originalURL(req, { })).to.equal('http://google.com/woot');
        expect(utils.originalURL(req, { proxy : false })).to.equal('http://google.com/woot');

        req.app = {
          get : function(name) {
            if (name === 'trust proxy') {
              return true;
            }
          }
        };

        expect(utils.originalURL(req)).to.equal('https://google.com/woot');
        expect(utils.originalURL(req), { }).to.equal('https://google.com/woot');
        expect(utils.originalURL(req), { proxy : false }).to.equal('https://google.com/woot');
        expect(utils.originalURL(req), { proxy : true }).to.equal('https://google.com/woot');
      });
    });
  });
});

function createVanillaRequest() {
  return {
    headers : {
      host : 'google.com'
    },
    connection : {
      encrypted : null
    },
    url : '/woot'
  };
}