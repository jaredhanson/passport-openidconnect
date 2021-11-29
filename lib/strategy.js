/**
 * Module dependencies.
 */
var passport = require('passport-strategy')
  , url = require('url')
  , util = require('util')
  , utils = require('./utils')
  , OAuth2 = require('oauth').OAuth2
  , Profile = require('./profile')
  , Context = require('./context')
  , SessionStateStore = require('./state/session')
  , AuthorizationError = require('./errors/authorizationerror')
  , TokenError = require('./errors/tokenerror')
  , InternalOAuthError = require('./errors/internaloautherror');


/**
 * Creates an instance of `OpenIDConnectStrategy`.
 *
 * The OpenID Connect authentication strategy authenticates requests using
 * OpenID Connect, which is an identity layer on top of the OAuth 2.0 protocol.
 *
 * @param {Object} options
 * @param {Function} verify
 * @access public
 */
function Strategy(options, verify) {
  options = options || {};
  
  if (!verify) { throw new TypeError('OpenIDConnectStrategy requires a verify function'); }
  if (!options.issuer) { throw new TypeError('OpenIDConnectStrategy requires an issuer option'); }
  if (!options.authorizationURL) { throw new TypeError('OpenIDConnectStrategy requires an authorizationURL option'); }
  if (!options.tokenURL) { throw new TypeError('OpenIDConnectStrategy requires a tokenURL option'); }
  if (!options.clientID) { throw new TypeError('OpenIDConnectStrategy requires a clientID option'); }
  
  passport.Strategy.call(this);
  this.name = 'openidconnect';
  this._verify = verify;
  this._passReqToCallback = options.passReqToCallback;
  
  // NOTE: The _oauth2 property is considered "protected".  Subclasses are
  //       allowed to use it when making protected resource requests to retrieve
  //       the user profile.
  this._oauth2 = new OAuth2(options.clientID,  options.clientSecret,
                            '', options.authorizationURL, options.tokenURL, options.customHeaders);
  this._oauth2.useAuthorizationHeaderforGET(true);
  if (options.agent) {
    this._oauth2.setAgent(options.agent);
  }
  
  this._issuer = options.issuer;
  this._callbackURL = options.callbackURL;
  this._scope = options.scope;
  this._responseMode = options.responseMode;

  this._prompt = options.prompt;
  this._display = options.display;
  this._uiLocales = options.uiLocales;
  this._loginHint = options.loginHint;
  this._maxAge = options.maxAge;
  this._acrValues = options.acrValues;
  this._idTokenHint = options.idTokenHint;
  this._nonce = options.nonce;
  this._claims = options.claims;
  
  var key = options.sessionKey || (this.name + ':' + url.parse(options.authorizationURL).hostname);
  this._stateStore = options.store || new SessionStateStore({ key: key });
  
  this._userInfoURL = options.userInfoURL;
  this._skipUserProfile = (options.skipUserProfile === undefined) ? function() {
    if ((options.passReqToCallback && verify.length >= 10) || (!options.passReqToCallback && verify.length >= 9)) { return false; }
    return true;
  } : options.skipUserProfile;

  this._trustProxy = options.proxy;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);


/**
 * Authenticate request by delegating to OpenID Connect provider.
 *
 * @param {http.IncomingMessage} req
 * @param {Object} options
 * @access protected
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
  
  var callbackURL = options.callbackURL || self._callbackURL;
  if (callbackURL) {
    var parsed = url.parse(callbackURL);
    if (!parsed.protocol) {
      // The callback URL is relative, resolve a fully qualified URL from the
      // URL of the originating request.
      callbackURL = url.resolve(utils.originalURL(req, { proxy: self._trustProxy }), callbackURL);
    }
  }
  
  var meta = {
    issuer: this._issuer,
    authorizationURL: this._oauth2._authorizeUrl,
    tokenURL: this._oauth2._accessTokenUrl,
    clientID: this._oauth2._clientId,
    callbackURL: callbackURL
  };

  if (req.query && req.query.code) {
    function restored(err, ctx, state) {
      if (err) { return self.error(err); }
      if (!ctx) {
        return self.fail(state, 403);
      }
      
      var code = req.query.code;
      
      var params = { grant_type: 'authorization_code' };
      if (callbackURL) { params.redirect_uri = callbackURL; }

      self._oauth2.getOAuthAccessToken(code, params, function(err, accessToken, refreshToken, params) {
        if (err) {
          if (err.statusCode && err.data) {
            try {
              var json = JSON.parse(err.data);
              if (json.error) {
                return self.error(new TokenError(json.error_description, json.error, json.error_uri));
              }
            } catch (_) {}
          }
          return self.error(new InternalOAuthError('Failed to obtain access token', err));
        }

        var idToken = params['id_token'];
        if (!idToken) { return self.error(new Error('ID token not present in token response')); }

        var components = idToken.split('.')
          , payload
          , claims;

        try {
          payload = new Buffer(components[1], 'base64').toString();
          claims = JSON.parse(payload);
        } catch (ex) {
          return self.error(ex);
        }
        
        if (!claims.iss) { return self.error(new Error('ID token missing issuer claim')); }
        if (!claims.sub) { return self.error(new Error('ID token missing subject claim')); }
        if (!claims.aud) { return self.error(new Error('ID token missing audience claim')); }
        if (!claims.exp) { return self.error(new Error('ID token missing expiration time claim')); }
        if (!claims.iat) { return self.error(new Error('ID token missing issued at claim')); }
        
        if (!(typeof claims.aud === 'string' || Array.isArray(claims.aud))) {
          return self.error(new Error('ID token audience claim not an array or string value'));
        }
        
        // https://openid.net/specs/openid-connect-basic-1_0.html#IDTokenValidation - check 1.
        if (claims.iss !== self._issuer) { return self.fail({ message: 'ID token not issued by expected OpenID provider.' }, 403); }

        // https://openid.net/specs/openid-connect-basic-1_0.html#IDTokenValidation - checks 2 and 3.
        if (typeof claims.aud === 'string') {
          if (claims.aud !== self._oauth2._clientId) { return self.fail({ message: 'ID token not intended for this relying party.' }, 403); }
        } else {
          if (claims.aud.indexOf(self._oauth2._clientId) === -1) { return self.fail({ message: 'ID token not intended for this relying party.' }, 403); }
          if (claims.aud.length > 1 && !claims.azp) { return self.fail({ message: 'ID token missing authorizied party claim.' }, 403); }
        }

        // https://openid.net/specs/openid-connect-basic-1_0.html#IDTokenValidation - check 4.
        if (claims.azp && claims.azp !== self._oauth2._clientId) { return self.fail({ message: 'ID token not issued to this relying party.' }, 403); }

        // Possible TODO: Add accounting for some clock skew.
        // https://openid.net/specs/openid-connect-basic-1_0.html#IDTokenValidation - check 5.
        if (claims.exp <= (Date.now() / 1000)) { return self.fail({ message: 'ID token has expired.' }, 403); }

        // Note: https://openid.net/specs/openid-connect-basic-1_0.html#IDTokenValidation - checks 6 and 7 are out of scope of this library.

        // https://openid.net/specs/openid-connect-basic-1_0.html#IDTokenValidation - check 8.
        if (ctx.maxAge && (!claims.auth_time || ((ctx.issued.valueOf() - (ctx.maxAge * 1000)) > (claims.auth_time * 1000)))) {
          return self.fail({ message: 'Too much time has elapsed since last authentication.' }, 403);
        }
        
        if (ctx.nonce && (claims.nonce !== ctx.nonce)) { return self.fail({ message: 'ID token contains invalid nonce.' }, 403); }

        self._shouldLoadUserProfile(req, claims, function(err, load) {
          if (err) { return self.error(err); };
          
          function loaded(uiProfile, json, body) {
            function verified(err, user, info) {
              if (err) { return self.error(err); }
              if (!user) { return self.fail(info); }

              info = info || {};
              if (state) { info.state = state; }
              self.success(user, info);
            }
            
            var idProfile = Profile.parse(claims);
            var profile = {};
            utils.merge(profile, idProfile);
            utils.merge(profile, uiProfile);
            
            if (uiProfile) {
              uiProfile._raw = body;
              uiProfile._json = json;
            }
            
            var context = Context.parse(claims);

            try {
              if (self._passReqToCallback) {
                var arity = self._verify.length;
                if (arity == 10) {
                  self._verify(req, claims.iss, uiProfile, idProfile, context, idToken, accessToken, refreshToken, params, verified);
                } else if (arity == 9) {
                  self._verify(req, claims.iss, profile, context, idToken, accessToken, refreshToken, params, verified);
                } else if (arity == 8) {
                  self._verify(req, claims.iss, profile, context, idToken, accessToken, refreshToken, verified);
                } else if (arity == 6) {
                  self._verify(req, claims.iss, profile, context, idToken, verified);
                } else if (arity == 5) {
                  self._verify(req, claims.iss, profile, context, verified);
                } else { // arity == 4
                  self._verify(req, claims.iss, profile, verified);
                }
              } else {
                var arity = self._verify.length;
                if (arity == 9) {
                  self._verify(claims.iss, uiProfile, idProfile, context, idToken, accessToken, refreshToken, params, verified);
                } else if (arity == 8) {
                  self._verify(claims.iss, profile, context, idToken, accessToken, refreshToken, params, verified);
                } else if (arity == 7) {
                  self._verify(claims.iss, profile, context, idToken, accessToken, refreshToken, verified);
                } else if (arity == 5) {
                  self._verify(claims.iss, profile, context, idToken, verified);
                } else if (arity == 4) {
                  self._verify(claims.iss, profile, context, verified);
                } else { // arity == 3
                  self._verify(claims.iss, profile, verified);
                }
              }
            } catch (ex) {
              return self.error(ex);
            }
          } // loaded

          if (!load) { return loaded(); }

          self._oauth2.get(self._userInfoURL, accessToken, function (err, body, res) {
            if (err) { return self.error(new InternalOAuthError('Failed to fetch user profile', err)); }

            var json;
            try {
              json = JSON.parse(body);
            } catch(ex) {
              return done(new Error('Failed to parse user profile'));
            }
            
            var profile = Profile.parse(json);
            loaded(profile, json, body);
          });
        }); // self._shouldLoadUserProfile
      }); // oauth2.getOAuthAccessToken
    } // restored

    var state = req.query.state;
    try {
      self._stateStore.verify(req, state, restored);
    } catch (ex) {
      return self.error(ex);
    }
  } else {
    var params = this.authorizationParams(options);
    params.response_type = 'code';
    if (this._responseMode) {
      params.response_mode = this._responseMode;
    }
    params.client_id = this._oauth2._clientId;
    if (callbackURL) { params.redirect_uri = callbackURL; }
    var scope = options.scope || this._scope;
    if (scope) {
      if (Array.isArray(scope)) { scope = scope.join(' '); }
      params.scope = 'openid ' + scope;
    } else {
      params.scope = 'openid';
    }
    
    var prompt = options.prompt || this._prompt;
    if (prompt) {
      params.prompt = prompt;
    }
    var display = options.display || this._display;
    if (display) {
      params.display = display;
    }
    var uiLocales = this._uiLocales;
    if (uiLocales) {
      params.ui_locales = uiLocales;
    }
    var loginHint = options.loginHint || this._loginHint;
    if (loginHint) {
      params.login_hint = loginHint;
    }
    var maxAge = this._maxAge;
    if (maxAge) {
      params.max_age = maxAge;
    }
    var acrValues = this._acrValues;
    if (acrValues) {
      params.acr_values = acrValues;
    }
    var idTokenHint = this._idTokenHint;
    if (idTokenHint) {
      params.id_token_hint = idTokenHint;
    }
    var nonce = this._nonce;
    if (nonce) {
      params.nonce = utils.uid(20);
    }
    var claims = this._claims;
    if (claims) {
      params.claims = JSON.stringify(claims);
    }
    
    var ctx = {};
    if (params.max_age) {
      ctx.maxAge = params.max_age;
      ctx.issued = new Date();
    }
    if (params.nonce) { ctx.nonce = params.nonce; }
    var state = options.state;

    function stored(err, state) {
      if (err) { return self.error(err); }
      if (!state) { return self.error(new Error('OpenID Connect state store did not yield state for authentication request')); }

      params.state = state;
      var parsed = url.parse(self._oauth2._authorizeUrl, true);
      utils.merge(parsed.query, params);
      delete parsed.search;
      var location = url.format(parsed);
      self.redirect(location);
    }
    
    try {
      this._stateStore.store(req, ctx, state, meta, stored);
    } catch (ex) {
      return this.error(ex);
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
Strategy.prototype._shouldLoadUserProfile = function(req, claims, done) {
  if (typeof this._skipUserProfile == 'function' && this._skipUserProfile.length > 2) {
    // async
    this._skipUserProfile(req, claims, function(err, skip) {
      if (err) { return done(err); }
      if (!skip) { return done(null, true); }
      return done(null, false);
    });
  } else {
    var skip = (typeof this._skipUserProfile == 'function') ? this._skipUserProfile(req, claims) : this._skipUserProfile;
    if (!skip) { return done(null, true); }
    return done(null, false);
  }
}

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
