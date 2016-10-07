var assert = require('assert');
var sinon = require('sinon');

// Code under test.
var Registrar = require('../lib/registrar');

describe('OpenID Connect Dynamic Registration', function () {
  describe('instantiation', function () {
    it('should require a getClientCallback', function () {
      assert.throws(function () { new Registrar(); }); // eslint-disable-line no-new
    });

    it('should have a resolve function', function () {
      var registrar = new Registrar({ getClientCallback: function () {} });
      assert(typeof registrar.resolve === 'function');
    });
  });

  describe.skip('resolve getClientCallback', function () {
    it('should check required client information', function () {
      var getClientCallback = sinon.stub();
      var callback = sinon.spy();
      var registrar = new Registrar({ getClientCallback: getClientCallback });

      registrar.resolve('myIssuer', callback);
      getClientCallback.yield('not object');

      assert(callback.args[0][0] instanceof Error);
    });
  });
});
