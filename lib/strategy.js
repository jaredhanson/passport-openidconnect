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
  //, setup = require('./setup')
  , InternalOAuthError = require('./errors/internaloautherror');


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
  
  // TODO: What's the recommended field name for OpenID Connect?
  this._identifierField = options.identifierField || 'openid_identifier';
  this._scope = options.scope;
  this._scopeSeparator = options.scopeSeparator || ' ';
  this._passReqToCallback = options.passReqToCallback;
  this._skipUserProfile = (options.skipUserProfile === undefined) ? false : options.skipUserProfile;
  
  this._setup = undefined;

  this._key = options.sessionKey || (this.name + ':' + url.parse(options.authorizationURL).hostname);
  this._stateStore = options.store || new SessionStateStore({ key: this._key });

  if (options.authorizationURL && options.tokenURL) {
    // This OpenID Connect strategy is configured to work with a specific
    // provider.  Override the discovery process with pre-configured endpoints.
    this.configure(require('./setup/manual')(options));
    //this.configure(require('./setup/dynamic')(options));
  } else {
    this.configure(require('./setup/dynamic')(options));
  }
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
    // TODO: Error information pertaining to OAuth 2.0 flows is encoded in the
    //       query parameters, and should be propagated to the application.
    return this.fail();
  }
  
  if (req.query && req.query.code) {
    
    function loaded(err, ok, state) {
      if (err) { return self.error(err); }
      if (!ok) {
        return self.fail(state, 403);
      }
      var meta = state;
      var code = req.query.code;

      var oauth2 = self._getOAuth2Client(meta);

      var callbackURL = options.callbackURL || meta.callbackURL;
      if (callbackURL) {
        var parsed = url.parse(callbackURL);
        if (!parsed.protocol) {
          // The callback URL is relative, resolve a fully qualified URL from the
          // URL of the originating request.
          callbackURL = url.resolve(utils.originalURL(req), callbackURL);
        }
      }

      oauth2.getOAuthAccessToken(code, { grant_type: 'authorization_code', redirect_uri: callbackURL }, function(err, accessToken, refreshToken, params) {
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

        var params = meta.params;

        if (params.nonce && (!jwtClaims.nonce || jwtClaims.nonce !== params.nonce)) {
          return self.error(new Error('Invalid nonce in id_token'));
        }

        if (params.max_age && (!jwtClaims.auth_time || ((meta.timestamp - params.max_age) > jwtClaims.auth_time))) {
          return self.error(new Error('auth_time in id_token not included or too old'));
        }

        var iss = jwtClaims.iss;
        var sub = jwtClaims.sub;
        // Prior to OpenID Connect Basic Client Profile 1.0 - draft 22, the
        // "sub" claim was named "user_id".  Many providers still issue the
        // claim under the old field, so fallback to that.
        if (!sub) {
          sub = jwtClaims.user_id;
        }

        // TODO: Ensure claims are validated per:
        //       http://openid.net/specs/openid-connect-basic-1_0.html#id_token

        self._shouldLoadUserProfile(iss, sub, function(err, load) {
          if (err) { return self.error(err); };

          if (load) {
            var parsed = url.parse(meta.userInfoURL, true);
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
            oauth2._request("GET", userInfoURL, { 'Authorization': "Bearer " + accessToken, 'Accept': "application/json" }, null, null, function (err, body, res) {
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
                profile.name = { familyName: json.family_name,
                                 givenName: json.given_name,
                                 middleName: json.middle_name };

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
      var arity = self._stateStore.verify.length;
      if (arity == 4) {
        self._stateStore.verify(req, state, meta, loaded);
      } else { // arity == 3
        self._stateStore.verify(req, state, loaded);
      }
    } catch (ex) {
      return self.error(ex);
    }
  } else {
    // The request being authenticated is initiating OpenID Connect
    // authentication.  Prior to redirecting to the provider, configuration will
    // be loaded.  The configuration is typically either pre-configured or
    // discovered dynamically.  When using dynamic discovery, a user supplies
    // their identifer as input.
  
    var identifier;
    if (req.body && req.body[this._identifierField]) {
      identifier = req.body[this._identifierField];
    } else if (req.query && req.query[this._identifierField]) {
      identifier = req.query[this._identifierField];
    }
  
    // FIXME: Hard coded for test purposes:
    //identifier = 'acct:paulej@packetizer.com';
    this._setup(identifier, function(err, config) {
      if (err) { return self.error(err); }

      // Required Parameters
      var meta = config;

      var callbackURL = options.callbackURL || config.callbackURL;
      if (callbackURL) {
        var parsed = url.parse(callbackURL);
        if (!parsed.protocol) {
          // The callback URL is relative, resolve a fully qualified URL from the
          // URL of the originating request.
          callbackURL = url.resolve(utils.originalURL(req), callbackURL);
        }
      }
      meta.callbackURL = callbackURL;

      var params = self.authorizationParams(options);
      params['response_type'] = 'code';
      params['client_id'] = config.clientID;
      if (callbackURL) { params.redirect_uri = callbackURL; }
      var scope = options.scope || self._scope;
      if (Array.isArray(scope)) { scope = scope.join(self._scopeSeparator); }
      if (scope) {
        params.scope = 'openid' + self._scopeSeparator + scope;
      } else {
        params.scope = 'openid';
      }

      // Optional Parameters

      var simple_optional_params = ['max_age', 'ui_locals', 'id_token_hint', 'login_hint', 'acr_values'];
      simple_optional_params.filter( x => { return x in config } ).map( y => { params[y] = config[y] } );

      if (config.display && ['page', 'popup', 'touch', 'wap'].indexOf(config.display) !== -1) params.display = config.display;
      if (config.prompt && ['none', 'login', 'consent', 'select_account'].indexOf(config.prompt) !== -1) params.prompt = config.prompt;

      if (config.nonce && typeof config.nonce === 'boolean') { params.nonce = utils.uid(20); }
      if (config.nonce && typeof config.nonce === 'number') { params.nonce = utils.uid(config.nonce); }
      if (config.nonce && typeof config.nonce === 'string') { params.nonce = config.nonce; }

      if (params.max_age) meta.timestamp = Math.floor(Date.now() / 1000);

      meta.params = params;
      for (param in params) {
        if (meta[param]) delete meta[param]; // Remove redundant information.
      }

      // State Storage/Management

      function stored(err, state) {
        if (err) { return self.error(err); }
        if (!state) { return self.error(new Error('Unable to generate required state parameter')); }

        params.state = state.handle;
        var location = config.authorizationURL + '?' + querystring.stringify(params);
        self.redirect(location);
      }

      try {
        var arity = self._stateStore.store.length;
        if (arity == 3) {
          self._stateStore.store(req, meta, stored);
        } else { // arity == 2
          self._stateStore.store(req, stored);
        }
      } catch (ex) {
        return self.error(ex);
      }
    }); // this.configure
  }
}

/**
 * Register a function used to configure the strategy.
 *
 * OpenID Connect is an identity layer on top of OAuth 2.0.  OAuth 2.0 requires
 * knowledge of certain endpoints (authorization, token, etc.) as well as a
 * client identifier (and corresponding secret) registered at the authorization
 * server.
 *
 * Configuration functions are responsible for loading this information.  This
 * is typically done via one of two popular mechanisms:
 *
 *   - The configuration is known ahead of time, and pre-configured via options
 *     to the strategy.
 *   - The configuration is dynamically loaded, using optional discovery and
 *     registration specifications.  (Note: Providers are not required to
 *     implement support for dynamic discovery and registration.  As such, there
 *     is no guarantee that this will result in successfully initiating OpenID
 *     Connect authentication.)
 *
 * @param {Function} fn
 * @api public
 */
Strategy.prototype.configure = function(identifier, done) {
  this._setup = identifier;
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
                    '', config.authorizationURL, config.tokenURL);
}

/**
 * Expose `Strategy`.
 */ 
module.exports = Strategy;
