var Profile = require('../lib/profile');

describe('Profile.parse', function() {
  
  describe('with groups claim as array of strings', function() {
    var profile;
    
    before(function() {
      profile = Profile.parse({
        sub: '248289761001',
        name: 'Jane Doe',
        given_name: 'Jane',
        family_name: 'Doe',
        email: 'janedoe@example.com',
        groups: ['admins', 'engineering', 'users']
      });
    });
    
    it('should normalize groups to array of objects', function() {
      expect(profile.groups).to.deep.equal([
        { value: 'admins' },
        { value: 'engineering' },
        { value: 'users' }
      ]);
    });
    
    it('should still parse other profile fields', function() {
      expect(profile.id).to.equal('248289761001');
      expect(profile.displayName).to.equal('Jane Doe');
      expect(profile.name.familyName).to.equal('Doe');
      expect(profile.name.givenName).to.equal('Jane');
      expect(profile.emails).to.deep.equal([ { value: 'janedoe@example.com' } ]);
    });
  });
  
  describe('with groups claim as single string', function() {
    var profile;
    
    before(function() {
      profile = Profile.parse({
        sub: '248289761001',
        groups: 'admins'
      });
    });
    
    it('should normalize to array with one object', function() {
      expect(profile.groups).to.deep.equal([
        { value: 'admins' }
      ]);
    });
  });
  
  describe('without groups claim', function() {
    var profile;
    
    before(function() {
      profile = Profile.parse({
        sub: '248289761001',
        name: 'Jane Doe',
        email: 'janedoe@example.com'
      });
    });
    
    it('should not set groups on profile', function() {
      expect(profile.groups).to.be.undefined;
    });
  });
  
  describe('with groups claim as empty array', function() {
    var profile;
    
    before(function() {
      profile = Profile.parse({
        sub: '248289761001',
        groups: []
      });
    });
    
    it('should not set groups on profile', function() {
      expect(profile.groups).to.be.undefined;
    });
  });
  
});
