var strategy = require('..');


describe('passport-openidconnect', function() {
    
  it('should export version', function() {
    expect(strategy.version).to.be.a('string');
  });
    
  it('should export Strategy', function() {
    expect(strategy.Strategy).to.be.a('function');
  });
  
  it('should export configuration functions', function() {
    expect(strategy.disco).to.be.a('function');
    expect(strategy.config).to.be.a('function');
    expect(strategy.register).to.be.a('function');
  });
  
  it('should export discovery mechanisms', function() {
    expect(strategy.discovery).to.be.an('object');
    expect(strategy.discovery.webfinger).to.be.a('function');
    expect(strategy.discovery.lrdd).to.be.a('function');
  });
  
});
