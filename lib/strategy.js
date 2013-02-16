/**
 * Module dependencies.
 */
var passport = require('passport')
  , url = require('url')
  , util = require('util')
  , utils = require('./utils')
  , OAuth2 = require('oauth').OAuth2
  , InternalOAuthError = require('./errors/internaloautherror');


function Strategy(options, verify) {
  options = options || {}
  passport.Strategy.call(this);
  this.name = 'openidconnect';
  this._verify = verify;
  
  if (!options.authorizationURL) throw new Error('OpenIDConnectStrategy requires a authorizationURL option');
  if (!options.tokenURL) throw new Error('OpenIDConnectStrategy requires a tokenURL option');
  if (!options.clientID) throw new Error('OpenIDConnectStrategy requires a clientID option');
  if (!options.clientSecret) throw new Error('OpenIDConnectStrategy requires a clientSecret option');

  // TODO: Implement support for discover and registration.  This means endpoint
  //       URLs and client IDs will need to be dynamically loaded, on a per-provider
  //       basis.  The above checks can be relaxed, once this is complete.

  this._authorizationURL = options.authorizationURL;
  this._tokenURL = options.tokenURL;
  this._userInfoURL = options.userInfoURL;
  
  this._clientID = options.clientID;
  this._clientSecret = options.clientSecret;
  this._callbackURL = options.callbackURL;
  
  this._scope = options.scope;
  this._scopeSeparator = options.scopeSeparator || ' ';
  this._passReqToCallback = options.passReqToCallback;
  this._skipUserProfile = (options.skipUserProfile === undefined) ? false : options.skipUserProfile;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);


Strategy.prototype.authenticate = function(req, options) {
  options = options || {};
  var self = this;
  
  if (req.query && req.query.error) {
    // TODO: Error information pertaining to OAuth 2.0 flows is encoded in the
    //       query parameters, and should be propagated to the application.
    return this.fail();
  }
  
  var callbackURL = options.callbackURL || this._callbackURL;
  if (callbackURL) {
    var parsed = url.parse(callbackURL);
    if (!parsed.protocol) {
      // The callback URL is relative, resolve a fully qualified URL from the
      // URL of the originating request.
      callbackURL = url.resolve(utils.originalURL(req), callbackURL);
    }
  }
  
  
  var oauth2 = new OAuth2(this._clientID,  this._clientSecret,
                          '', this._authorizationURL, this._tokenURL);
  
  if (req.query && req.query.code) {
    var code = req.query.code;
    
    oauth2.getOAuthAccessToken(code, { grant_type: 'authorization_code', redirect_uri: callbackURL }, function(err, accessToken, refreshToken, params) {
      if (err) { return self.error(new InternalOAuthError('failed to obtain access token', err)); }
      
      console.log('TOKEN');
      console.log('AT: ' + accessToken);
      console.log('RT: ' + refreshToken);
      console.log(params);
      console.log('----');
      
      var idToken = params['id_token'];
      // TODO: If no idToken, throw error
      var idTokenSegments = idToken.split('.')
        , jwtHeaderStr
        , jwtClaimsStr
        , jwtHeader
        , jwtClaims;
      
      // TODO: Try catch this to trap JSON parse errors.
      jwtHeaderStr = new Buffer(idTokenSegments[0], 'base64').toString();
      jwtClaimsStr = new Buffer(idTokenSegments[1], 'base64').toString();
      
      console.log('jwtHeaderEnc: ' + jwtHeaderStr);
      console.log('jwtClaimsEnc: ' + jwtClaimsStr);
      
      jwtHeader = JSON.parse(jwtHeaderStr);
      jwtClaims = JSON.parse(jwtClaimsStr);
      
      console.log(jwtHeader);
      console.log(jwtClaims);
      
      // TODO: Validate JWT signature?  OpenID spec indicates that isn't necessary.
      // TODO: Validate aud and iss in JWT Claims Set
      
      var iss = jwtClaims.iss;
      var sub = jwtClaims.sub;
      // Prior to OpenID Connect Basic Client Profile 1.0 - draft 22, the
      // "sub" claim was named "user_id".  Many providers still issue the
      // claim under the old field, so fallback to that.
      if (!sub) {
        sub = jwtClaims.user_id;
      }
      
      self._shouldLoadUserProfile(iss, sub, function(err, load) {
        if (err) { return self.error(err); };
        
        console.log('LOAD: ' + load);
        
        if (load) {
        
          var parsed = url.parse(self._userInfoURL, true);
          parsed.query['schema'] = 'openid';
          delete parsed.search;
          var userInfoURL = url.format(parsed);
          
          console.log('fetch profile: ' + userInfoURL);
          
          // NOTE: We are calling node-oauth's internal `_request` function (as
          //       opposed to `get`) in order to send the access token in the
          //       `Authorization` header rather than as a query parameter.
          //
          //       Additionally, the master branch of node-oauth (as of
          //       2013-02-16) will include the access token in *both* headers
          //       and query parameters, which is a violation of the spec.
          //       Setting the fifth argument of `_request` to `null` works
          //       around this issue.
          
          //oauth2.get(userInfoURL, accessToken, function (err, body, res) {
          oauth2._request("GET", userInfoURL, { 'Authorization': "Bearer " + accessToken, 'Accept': "application/json" }, null, null, function (err, body, res) {
            if (err) { return self.error(new InternalOAuthError('failed to fetch user profile', err)); }
            
            console.log('PROFILE');
            console.log(body);
            console.log('-------');
          });
        }
      });
      
      /*
      self._loadUserProfile(accessToken, function(err, profile) {
        if (err) { return self.error(err); };
        
        function verified(err, user, info) {
          if (err) { return self.error(err); }
          if (!user) { return self.fail(info); }
          self.success(user, info);
        }
        
        if (self._passReqToCallback) {
          var arity = self._verify.length;
          if (arity == 6) {
            self._verify(req, accessToken, refreshToken, params, profile, verified);
          } else { // arity == 5
            self._verify(req, accessToken, refreshToken, profile, verified);
          }
        } else {
          var arity = self._verify.length;
          if (arity == 5) {
            self._verify(accessToken, refreshToken, params, profile, verified);
          } else { // arity == 4
            self._verify(accessToken, refreshToken, profile, verified);
          }
        }
      });
      */
    });
  } else {
    var params = this.authorizationParams(options);
    var params = {};
    params['response_type'] = 'code';
    params['redirect_uri'] = callbackURL;
    var scope = options.scope || this._scope;
    if (Array.isArray(scope)) { scope = scope.join(this._scopeSeparator); }
    if (scope) {
      params.scope = 'openid' + this._scopeSeparator + scope;
    } else {
      params.scope = 'openid';
    }
    // TODO: Add support for automatically generating a random state for verification.
    var state = options.state;
    if (state) { params.state = state; }
    // TODO: Implement support for standard OpenID Connect params (display, prompt, etc.)
    
    var location = oauth2.getAuthorizeUrl(params);
    console.log('REDIRECT: ' + location);
    this.redirect(location);
  }
}

/**
 * Return extra parameters to be included in the authorization request.
 *
 * Some OpenID Connect providers allow additional, non-standard parameters to be
 * included when requesting authorization.  Since these parameters are not
 * standardized by the OpenID Connect specification, OpenID Connect-based
 * authentication strategies can overrride this function in order to populate
 * these parameters as required by the provider.
 *
 * @param {Object} options
 * @return {Object}
 * @api protected
 */
Strategy.prototype.authorizationParams = function(options) {
  return {};
}

/**
 * Check if should load user profile, contingent upon options.
 *
 * @param {String} issuer
 * @param {String} subject
 * @param {Function} done
 * @api private
 */
Strategy.prototype._shouldLoadUserProfile = function(issuer, subject, done) {
  if (typeof this._skipUserProfile == 'function' && this._skipUserProfile.length > 1) {
    // async
    this._skipUserProfile(issuer, subject, function(err, skip) {
      if (err) { return done(err); }
      if (!skip) { return done(null, true); }
      return done(null, false);
    });
  } else {
    var skip = (typeof this._skipUserProfile == 'function') ? this._skipUserProfile(issuer, subject) : this._skipUserProfile;
    if (!skip) { return done(null, true); }
    return done(null, false);
  }
}


/**
 * Expose `Strategy`.
 */ 
module.exports = Strategy;
