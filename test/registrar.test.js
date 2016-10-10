var assert = require('assert');
var sinon = require('sinon');
var proxyquire = require('proxyquire');

// Mocks, stubs etc.
var requestPost = sinon.stub(require('request'), 'post');

// Code under test.
var Registrar = proxyquire('../lib/registrar', { request: { post: requestPost } });

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

  describe('registration request', function () {
    it('should POST the clientMetadata as JSON to registrationURL', function () {
      requestPost.reset();

      var getClientCallback = sinon.stub();
      var callback = sinon.spy();

      var registrar = new Registrar({
        getClientCallback: getClientCallback,
        clientMetadata: { foo: 'bar' }
      });

      registrar.resolve({ registrationURL: 'myRegUrl', issuer: 'myIssuer' }, callback);

      getClientCallback.yield(null, null); // Needed to pass on to the registration.

      assert.equal(requestPost.callCount, 1);
      assert.equal(requestPost.args[0][0].uri, 'myRegUrl');
      assert.deepEqual(requestPost.args[0][0].json, { foo: 'bar' });
    });

    it('should fail on bad status code', function () {
      requestPost.reset();
      var callback = sinon.spy();

      var registrar = new Registrar({ getClientCallback: function (i, cb) { cb(null, null); } });
      registrar.resolve({ registrationURL: 'myRegUrl', issuer: 'myIssuer' }, callback);
      requestPost.yield(null, { statusCode: 500 }, null);

      assert.equal(callback.callCount, 1);
      assert(callback.args[0][0] instanceof Error);
    });

    it('should fail on missing client_id', function () {
      requestPost.reset();
      var callback = sinon.spy();

      var registrar = new Registrar({ getClientCallback: function (i, cb) { cb(null, null); } });
      registrar.resolve({ registrationURL: 'myRegUrl', issuer: 'myIssuer' }, callback);
      requestPost.yield(null, { statusCode: 201 }, {});

      assert.equal(callback.callCount, 1);
      assert(callback.args[0][0] instanceof Error);
    });

    it('should fail on client_secret without expiration', function () {
      requestPost.reset();
      var callback = sinon.spy();

      var registrar = new Registrar({ getClientCallback: function (i, cb) { cb(null, null); } });
      registrar.resolve({ registrationURL: 'myRegUrl', issuer: 'myIssuer' }, callback);
      requestPost.yield(null, { statusCode: 201 }, { client_id: 1, client_secret: 42 });

      assert.equal(callback.callCount, 1);
      assert(callback.args[0][0] instanceof Error);
    });

    it('should yield formatted client on success', function () {
      requestPost.reset();
      var callback = sinon.spy();

      var registrar = new Registrar({ getClientCallback: function (i, cb) { cb(null, null); } });
      registrar.resolve({ registrationURL: 'myRegUrl', issuer: 'myIssuer' }, callback);
      requestPost.yield(null, { statusCode: 201 }, { client_id: 1 });

      assert.equal(callback.callCount, 1);
      assert.strictEqual(callback.args[0][0], null);
      assert.deepEqual(callback.args[0][1], { id: 1, _json: { client_id: 1 } });
    });
  });

  describe('getClientCallback', function () {
    it('should use client if given', function () {
      var getClientCallback = sinon.stub();
      var callback = sinon.spy();

      var registrar = new Registrar({ getClientCallback: getClientCallback });
      registrar.resolve({ registrationURL: 'myRegUrl', issuer: 'myIssuer' }, callback);
      getClientCallback.yield(null, { id: 'foo' });

      assert.equal(callback.callCount, 1);
      assert.strictEqual(callback.args[0][0], null);
      assert.deepEqual(callback.args[0][1], { id: 'foo' });
    });

    it('should fail if getClientCallback errors', function () {
      var getClientCallback = sinon.stub();
      var callback = sinon.spy();

      var registrar = new Registrar({ getClientCallback: getClientCallback });
      registrar.resolve({ registrationURL: 'myRegUrl', issuer: 'myIssuer' }, callback);
      getClientCallback.yield('myError');

      assert.equal(callback.callCount, 1);
      assert.strictEqual(callback.args[0][0], 'myError');
    });
  });

  describe('saveClientCallback', function () {
    it('should save client after registration', function () {
      requestPost.reset();

      var saveClientCallback = sinon.stub();
      var callback = sinon.spy();

      var registrar = new Registrar({
        getClientCallback: function (i, cb) { cb(null, null); },
        saveClientCallback: saveClientCallback
      });
      registrar.resolve({ registrationURL: 'myRegUrl', issuer: 'myIssuer' }, callback);
      requestPost.yield(null, { statusCode: 201 }, { client_id: 1 });

      assert.equal(saveClientCallback.callCount, 1);
      assert.deepEqual(saveClientCallback.args[0][0], { id: 1, _json: { client_id: 1 } });
    });

    it('should fail if saveClientCallback errors', function () {
      requestPost.reset();

      var saveClientCallback = sinon.stub();
      var callback = sinon.spy();

      var registrar = new Registrar({
        getClientCallback: function (i, cb) { cb(null, null); },
        saveClientCallback: saveClientCallback
      });
      registrar.resolve({ registrationURL: 'myRegUrl', issuer: 'myIssuer' }, callback);
      requestPost.yield(null, { statusCode: 201 }, { client_id: 1 });
      saveClientCallback.yield('myError');

      assert.equal(callback.callCount, 1);
      assert.equal(callback.args[0][0], 'myError');
    });

    it('should pass on saveClientCallback\'s client object if modified', function () {
      requestPost.reset();

      var saveClientCallback = sinon.stub();
      var callback = sinon.spy();

      var registrar = new Registrar({
        getClientCallback: function (i, cb) { cb(null, null); },
        saveClientCallback: saveClientCallback
      });
      registrar.resolve({ registrationURL: 'myRegUrl', issuer: 'myIssuer' }, callback);
      requestPost.yield(null, { statusCode: 201 }, { client_id: 1 });
      saveClientCallback.yield(null, { id: 'one' });

      assert.equal(callback.callCount, 1);
      assert.strictEqual(callback.args[0][0], null);
      assert.deepEqual(callback.args[0][1], { id: 'one' });
    });
  });
});
