exports.parse = function(json) {
  var profile = {};
  profile.id = json.sub;
  // Prior to OpenID Connect Basic Client Profile 1.0 - draft 22, the "sub"
  // claim was named "user_id".  Many providers still use the old name, so
  // fallback to that.
  if (!profile.id) {
    profile.id = json.user_id;
  }
  
  if (json.name) { profile.displayName = json.name; }
  if (json.preferred_username) { profile.username = json.preferred_username; }
  if (json.family_name || json.given_name || json.middle_name) {
    profile.name = {};
    if (json.family_name) { profile.name.familyName = json.family_name; }
    if (json.given_name) { profile.name.givenName = json.given_name; }
    if (json.middle_name) { profile.name.middleName = json.middle_name; }
  }
  if (json.email) { profile.emails = [ { value: json.email } ]; }
  
  return profile;
};
