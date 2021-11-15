/**
 * Module dependencies.
 */
var passport = require('passport-strategy')
  , url = require('url')
  , querystring= require('querystring')
  , util = require('util')
  , utils = require('./utils')
  , OAuth2 = require('oauth').OAuth2
  , SessionStateStore = require('./state/session')
  , InternalOAuthError = require('./errors/internaloautherror')
  , AuthorizationError = require('./errors/authorizationerror');


/**
 * `Strategy` constructor.
 *
 * The OpenID Connect authentication strategy authenticates requests using
 * OpenID Connect, which is an identity layer on top of the OAuth 2.0 protocol.
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  options = options || {};
  passport.Strategy.call(this);
  this.name = 'openidconnect';
  this._verify = verify;
  
  // NOTE: The _oauth2 property is considered "protected".  Subclasses are
  //       allowed to use it when making protected resource requests to retrieve
  //       the user profile.
  this._oauth2 = new OAuth2(options.clientID,  options.clientSecret,
                            '', options.authorizationURL, options.tokenURL, options.customHeaders);
  if (options.agent) {
    this._oauth2.setAgent(options.agent);
  }
  
  // TODO: Make sure this is required
  this._issuer = options.issuer;
  this._callbackURL = options.callbackURL;
  this._userInfoURL = options.userInfoURL;
  
  
  this._scope = options.scope;
  this._trustProxy = options.proxy;
  
  this._prompt = options.prompt;
  this._display = options.display;
  this._uiLocales = options.uiLocales;
  this._maxAge = options.maxAge;
  this._acrValues = options.acrValues;
  this._idTokenHint = options.idTokenHint;
  this._loginHint = options.loginHint;
  this._claims = options.claims;
  this._nonce = options.nonce;
  this._responseMode = options.responseMode;
  this._passReqToCallback = options.passReqToCallback;
  this._skipUserProfile = (options.skipUserProfile === undefined) ? false : options.skipUserProfile;

  this._key = options.sessionKey || (this.name + ':' + url.parse(options.authorizationURL).hostname);
  this._stateStore = options.store || new SessionStateStore({ key: this._key });
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);


/**
 * Authenticate request by delegating to an OpenID Connect provider.
 *
 * @param {Object} req
 * @param {Object} options
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {
  options = options || {};
  var self = this;

  if (req.query && req.query.error) {
    if (req.query.error == 'access_denied') {
      return this.fail({ message: req.query.error_description });
    } else {
      return this.error(new AuthorizationError(req.query.error_description, req.query.error, req.query.error_uri));
    }
  }

  if (req.query && req.query.code) {

    function loaded(err, ok, state) {
      if (err) { return self.error(err); }
      if (!ok) {
        return self.fail(state, 403);
      }
      var code = req.query.code;
      var ctx = {};
      if (typeof ok == 'object') {
        ctx = ok;
      }
    
      var meta = state;
      meta = meta || {};
      meta.params = meta.params || {};
      
      var callbackURL = options.callbackURL || self._callbackURL;
      if (callbackURL) {
        var parsed = url.parse(callbackURL);
        if (!parsed.protocol) {
          // The callback URL is relative, resolve a fully qualified URL from the
          // URL of the originating request.
          callbackURL = url.resolve(utils.originalURL(req, { proxy: self._trustProxy }), callbackURL);
        }
      }

      self._oauth2.getOAuthAccessToken(code, { grant_type: 'authorization_code', redirect_uri: callbackURL }, function(err, accessToken, refreshToken, params) {
        if (err) { return self.error(new InternalOAuthError('failed to obtain access token', err)); }

        var idToken = params['id_token'];
        if (!idToken) { return self.error(new Error('ID Token not present in token response')); }

        var idTokenSegments = idToken.split('.')
          , jwtClaimsStr
          , jwtClaims;

        try {
          jwtClaimsStr = new Buffer(idTokenSegments[1], 'base64').toString();
          jwtClaims = JSON.parse(jwtClaimsStr);
        } catch (ex) {
          return self.error(ex);
        }
        
        var missing = ['iss', 'sub', 'aud', 'exp', 'iat'].filter( function(param) { return !jwtClaims[param] } );
        if (missing.length) return self.error(new Error('id token is missing required parameter(s) - ' + missing.join(', ')));

        // https://openid.net/specs/openid-connect-basic-1_0.html#IDTokenValidation - check 1.
        if (jwtClaims.iss !== self._issuer) return self.fail({ message: 'ID token not issued by expected OpenID provider.' }, 403);

        // https://openid.net/specs/openid-connect-basic-1_0.html#IDTokenValidation - checks 2 and 3.
        if (typeof jwtClaims.aud === 'string') {
          if (jwtClaims.aud !== self._oauth2._clientId) return self.fail({ message: 'aud parameter does not include this client - is: '
                                                                           + jwtClaims.aud + ' | expected: ' + self._oauth2._clientId }, 403);
        } else if (Array.isArray(jwtClaims.aud)) {
          if (jwtClaims.aud.indexOf(self._oauth2._clientId) === -1) return self.fail({ message: 'aud parameter does not include this client - is: ' +
                                                                                       jwtClaims.aud + ' | expected to include: ' + self._oauth2._clientId }, 403);
          if (jwtClaims.aud.length > 1 && !jwtClaims.azp) return self.fail({ message: 'azp parameter required with multiple audiences'}, 403);
        } else {
          return self.error(new Error('Invalid aud parameter type'));
        }

        // https://openid.net/specs/openid-connect-basic-1_0.html#IDTokenValidation - check 4.
        if (jwtClaims.azp && jwtClaims.azp !== self._oauth2._clientId) return self.fail({ message: 'this client is not the authorized party - ' +
                                                                                          'expected: ' + self._oauth2._clientId + ' | is: ' + jwtClaims.azp }, 403);

        // Possible TODO: Add accounting for some clock skew.
        // https://openid.net/specs/openid-connect-basic-1_0.html#IDTokenValidation - check 5.
        if (jwtClaims.exp < (Date.now() / 1000)) return self.error(new Error('id token has expired'));

        // Note: https://openid.net/specs/openid-connect-basic-1_0.html#IDTokenValidation - checks 6 and 7 are out of scope of this library.

        // https://openid.net/specs/openid-connect-basic-1_0.html#IDTokenValidation - check 8.
        if (meta.params.max_age && (!jwtClaims.auth_time || ((meta.timestamp - meta.params.max_age) > jwtClaims.auth_time))) {
          return self.error(new Error('auth_time in id_token not included or too old'));
        }
        
        if (ctx.nonce && (jwtClaims.nonce !== ctx.nonce)) {
          return self.fail({ message: 'Invalid nonce in id_token' }, 403);
        }

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

          if (load) {
            var parsed = url.parse(self._userInfoURL, true);
            parsed.query['schema'] = 'openid';
            delete parsed.search;
            var userInfoURL = url.format(parsed);

            // NOTE: We are calling node-oauth's internal `_request` function (as
            //       opposed to `get`) in order to send the access token in the
            //       `Authorization` header rather than as a query parameter.
            //
            //       Additionally, the master branch of node-oauth (as of
            //       2013-02-16) will include the access token in *both* headers
            //       and query parameters, which is a violation of the spec.
            //       Setting the fifth argument of `_request` to `null` works
            //       around this issue.  I've noted this in comments here:
            //       https://github.com/ciaranj/node-oauth/issues/117

            //oauth2.get(userInfoURL, accessToken, function (err, body, res) {
            self._oauth2._request("GET", userInfoURL, { 'Authorization': "Bearer " + accessToken, 'Accept': "application/json" }, null, null, function (err, body, res) {
              if (err) { return self.error(new InternalOAuthError('failed to fetch user profile', err)); }

              var profile = {};

              try {
                var json = JSON.parse(body);

                profile.id = json.sub;
                // Prior to OpenID Connect Basic Client Profile 1.0 - draft 22, the
                // "sub" key was named "user_id".  Many providers still use the old
                // key, so fallback to that.
                if (!profile.id) {
                  profile.id = json.user_id;
                }

                profile.displayName = json.name;
                profile.username = json.preferred_username;
                profile.name = { familyName: json.family_name,
                                 givenName: json.given_name,
                                 middleName: json.middle_name };
                profile.emails = [{ value: json.email }];

                profile._raw = body;
                profile._json = json;

                onProfileLoaded(profile);
              } catch(ex) {
                return self.error(ex);
              }
            });
          } else {
            onProfileLoaded();
          }

          function onProfileLoaded(profile) {
            function verified(err, user, info) {
              if (err) { return self.error(err); }
              if (!user) { return self.fail(info); }

              info = info || {};
              if (state) { info.state = state; }
              self.success(user, info);
            }

            if (self._passReqToCallback) {
              var arity = self._verify.length;
              if (arity == 9) {
                self._verify(req, iss, sub, profile, jwtClaims, accessToken, refreshToken, params, verified);
              } else if (arity == 8) {
                self._verify(req, iss, sub, profile, accessToken, refreshToken, params, verified);
              } else if (arity == 7) {
                self._verify(req, iss, sub, profile, accessToken, refreshToken, verified);
              } else if (arity == 5) {
                self._verify(req, iss, sub, profile, verified);
              } else { // arity == 4
                self._verify(req, iss, sub, verified);
              }
            } else {
              var arity = self._verify.length;
              if (arity == 8) {
                self._verify(iss, sub, profile, jwtClaims, accessToken, refreshToken, params, verified);
              } else if (arity == 7) {
                self._verify(iss, sub, profile, accessToken, refreshToken, params, verified);
              } else if (arity == 6) {
                self._verify(iss, sub, profile, accessToken, refreshToken, verified);
              } else if (arity == 4) {
                self._verify(iss, sub, profile, verified);
              } else { // arity == 3
                self._verify(iss, sub, verified);
              }
            }
          } // onProfileLoaded
        }); // self._shouldLoadUserProfile
      }); // oauth2.getOAuthAccessToken
    } // loaded

    var state = req.query.state;
    try {
      self._stateStore.verify(req, state, loaded);
    } catch (ex) {
      return self.error(ex);
    }
  } else {
    // The request being authenticated is initiating OpenID Connect
    // authentication.  Prior to redirecting to the provider, configuration will
    // be loaded.  The configuration is typically either pre-configured or
    // discovered dynamically.  When using dynamic discovery, a user supplies
    // their identifer as input.
    var meta = {};
    meta.issuer = self._issuer;
    meta.authorizationURL = self._oauth2._authorizeUrl;
    meta.tokenURL = self._oauth2._accessTokenUrl;
    meta.clientID = self._oauth2._clientId;

    var callbackURL = options.callbackURL || self._callbackURL;
    if (callbackURL) {
      var parsed = url.parse(callbackURL);
      if (!parsed.protocol) {
        // The callback URL is relative, resolve a fully qualified URL from the
        // URL of the originating request.
        callbackURL = url.resolve(utils.originalURL(req, { proxy: self._trustProxy }), callbackURL);
      }
    }
    meta.callbackURL = callbackURL;

    var params = self.authorizationParams(options);
    params['response_type'] = 'code';
    if (self._responseMode) {
      params.response_mode = self._responseMode;
    }
    
    params['client_id'] = self._oauth2._clientId;
    if (callbackURL) { params.redirect_uri = callbackURL; }
    var scope = options.scope || self._scope;
    if (Array.isArray(scope)) { scope = scope.join(' '); }
    if (scope) {
      params.scope = 'openid ' + scope;
    } else {
      params.scope = 'openid';
    }

    // Optional Parameters
    var maxAge = self._maxAge;
    if (maxAge) {
      params.max_age = maxAge;
    }
    var acrValues = self._acrValues;
    if (acrValues) {
      params.acr_values = acrValues;
    }
    var display = options.display || self._display;
    if (display) {
      params.display = display;
    }
    var uiLocales = self._uiLocales;
    if (uiLocales) {
      params.ui_locales = uiLocales;
    }
    var idTokenHint = self._idTokenHint;
    if (idTokenHint) {
      params.id_token_hint = idTokenHint;
    }
    var loginHint = options.loginHint || self._loginHint;
    if (loginHint) {
      params.login_hint = loginHint;
    }

    var claims = self._claims;
    if (claims) {
      params.claims = JSON.stringify(claims);
    }

    var display = self._display;
    if (display) {
      params.display = display;
    }
    
    var prompt = self._prompt;
    if (prompt) {
      params.prompt = prompt;
    }

    var nonce = self._nonce;
    if (nonce && typeof nonce == 'boolean') {
      params.nonce = utils.uid(20);
    }
    
    var ctx = {};
    if (params.nonce) { ctx.nonce = params.nonce; }

    // TODO: nonce support
    //if (config.nonce && typeof config.nonce === 'boolean') { params.nonce = utils.uid(20); }
    //if (config.nonce && typeof config.nonce === 'number') { params.nonce = utils.uid(config.nonce); }
    //if (config.nonce && typeof config.nonce === 'string') { params.nonce = config.nonce; }

    //if (params.max_age) meta.timestamp = Math.floor(Date.now() / 1000);

    // State Storage/Management
    var state = options.state;

    function stored(err, state) {
      if (err) { return self.error(err); }
      if (!state) { return self.error(new Error('Unable to generate required state parameter')); }

      params.state = state;
      var location = self._oauth2._authorizeUrl + '?' + querystring.stringify(params);
      self.redirect(location);
    }

    try {
      var arity = self._stateStore.store.length;
      if (arity == 5) {
        self._stateStore.store(req, ctx, state, meta, stored);
        // TODO: Put the change from 4 arity to 5 arity in the changleog
        //self._stateStore.store(req, state, meta, stored);
      } else if (arity == 3) {
        self._stateStore.store(req, meta, stored);
      } else { // arity == 2
        self._stateStore.store(req, stored);
      }
    } catch (ex) {
      return self.error(ex);
    }
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

Strategy.prototype._getOAuth2Client = function (config) {
  return new OAuth2(config.clientID, config.clientSecret,
                    '', config.authorizationURL, config.tokenURL,
                    config.customHeaders);
}

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
