module.exports = function() {
  
  return function(provider, done) {
    console.log('Register at: ' + provider.registrationURL);
  }
}
