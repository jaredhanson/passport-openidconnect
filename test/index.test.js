/* eslint-env mocha */
/* global expect */

var openid = require('index');


describe('passport-openid', function() {

  it('should export version', function() {
    expect(openid.version).to.be.a('string');
  });

  it('should export Strategy', function() {
    expect(openid.Strategy).to.be.a('function');
  });

  it('should export configuration functions', function() {
    expect(openid.disco).to.be.a('function');
    expect(openid.config).to.be.a('function');
    expect(openid.register).to.be.a('function');
  });

  it('should export discovery mechanisms', function() {
    expect(openid.discovery).to.be.an('object');
    expect(openid.discovery.webfinger).to.be.a('function');
    expect(openid.discovery.lrdd).to.be.a('function');
  });

});
