var openid = require('..');


describe('package', function() {
    
  it('should export Strategy constructor as module', function() {
    expect(openid).to.be.a('function');
    expect(openid).to.equal(openid.Strategy);
  });
    
  it('should export Strategy constructor', function() {
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
