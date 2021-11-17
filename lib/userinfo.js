exports.parse = function(json) {
  var profile = {};
  profile.id = json.sub;
  // Prior to OpenID Connect Basic Client Profile 1.0 - draft 22, the "sub"
  // claim was named "user_id".  Many providers still use the old name, so
  // fallback to that.
  if (!profile.id) {
    profile.id = json.user_id;
  }

  profile.displayName = json.name;
  profile.username = json.preferred_username;
  profile.name = { familyName: json.family_name,
                   givenName: json.given_name,
                   middleName: json.middle_name };
  profile.emails = [ { value: json.email } ];
  
  return profile;
};
