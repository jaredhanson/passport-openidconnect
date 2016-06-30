/**
 * Module dependencies.
 */
var passport = require('passport'),
    url = require('url'),
    querystring = require('querystring'),
    util = require('util'),
    utils = require('./utils'),
    OAuth2 = require('oauth').OAuth2,
    setup = require('./setup'),
    InternalOAuthError = require('./errors/internaloautherror'),
    jwt = require('jsonwebtoken');


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
function Strategy(options) {
    options = options || {};
    passport.Strategy.call(this);
    this.name = 'openidconnect';
    this._verify = options.verify;
    this._generateNonce = options.generateNonce;
    this._jwtAlgorithm = options.jwtAlgorithm || 'SHA256';

    this._identifierField = options.identifierField || 'openid_identifier';
    this._scope = options.scope;
    this._scopeSeparator = options.scopeSeparator || ' ';

    this._configurers = [];

    if (options.authorizationURL && options.tokenURL) {
        // This OpenID Connect strategy is configured to work with a specific
        // provider.  Override the discovery process with pre-configured endpoints.
        this.configure(function (identifier, done) {
            return done(null, {
                authorizationURL: options.authorizationURL,
                tokenURL: options.tokenURL,
                clientID: options.clientID,
                clientSecret: options.clientSecret,
                callbackURL: options.callbackURL
            });
        });
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
Strategy.prototype.authenticate = function (req, options) {
    options = options || {};
    var self = this;

    if (req.query && req.query.error) {
        // TODO: Error information pertaining to OAuth 2.0 flows is encoded in the
        //       query parameters, and should be propagated to the application.
        return this.fail();
    }

    var callbackURL = options.callbackURL || config.callbackURL;
    if (callbackURL) {
        var parsed = url.parse(callbackURL);
        if (!parsed.protocol) {
            // The callback URL is relative, resolve a fully qualified URL from the
            // URL of the originating request.
            callbackURL = url.resolve(utils.originalURL(req), callbackURL);
        }
    }

    if (req.query && req.query.code) {
        // If there's a state in the qs, we need to verify it matches our cookie
        if (req.query.state && options.response) {
            var failed = false;
            // Ensure we have cookie-parser middleware for cookie manipulation
            require('cookie-parser')()(req, options.response, function (err) {
                if (err) {
                    console.error('error parsing cookies with cookie-parser middleware', err);
                    return failed = true;
                }

                var state = req.query.state,
                    cookieState = req.cookies['openid-connect-state'];
                // Extract the state cookie and remove it from the user's cookies
                options.response.clearCookie('openid-connect-state');
                if (!cookieState || state !== cookieState) {
                    console.error('openid-connect auth failed, state is invalid. Expected ' + state + ' but cookie was ' + cookieState);
                    return failed = true;
                }
            });
            if (failed) {
                return self.fail();
            }
        }
        var code = req.query.code;

        this.configure(null, function (err, config) {
            if (err) {
                return self.error(err);
            }

            var oauth2 = new OAuth2(config.clientID, config.clientSecret, '', config.authorizationURL, config.tokenURL);

            oauth2.getOAuthAccessToken(code, {
                grant_type: 'authorization_code',
                redirect_uri: callbackURL
            }, function (err, accessToken, refreshToken, params) {
                if (err) {
                    return self.error(new InternalOAuthError('failed to obtain access token', err));
                }

                console.log('TOKEN');
                console.log(params);

                var idToken = params['id_token'];
                if (!idToken) {
                    return self.error(new Error('ID Token not present in token response'));
                }

                try {
                    var decoded = jwt.verify(idToken, config.clientSecret, { algorithm: self._jwtAlgorithm });
                } catch(err) {
                    return self.error(err);
                }

                function verified(err, user, info) {
                    if (err) { return self.error(err); }
                    if (!user) { return self.fail(info); }
                    self.success(user, info);
                }

                self._verify(req, decoded, verified);

            });
        });
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

        this.configure(identifier, function (err, config) {
            if (err) {
                return self.error(err);
            }

            var params = self.authorizationParams(req, options);
            params['response_type'] = 'code';
            params['client_id'] = config.clientID;
            params['redirect_uri'] = callbackURL;
            var scope = options.scope || self._scope;
            if (Array.isArray(scope)) {
                scope = scope.join(self._scopeSeparator);
            }
            if (scope) {
                params.scope = 'openid' + self._scopeSeparator + scope;
            } else {
                params.scope = 'openid';
            }

            // If there is a state param, we need to store it in a cookie so we can verify it later
            if (params['state'] && options.response) {
                // Write cookie to the current domain
                // Ensure we have cookie-parser middleware for cookie manipulation
                require('cookie-parser')()(req, options.response, function (err) {
                    if (!err) {
                        options.response.cookie('openid-connect-state', params['state'], { httpOnly: true });
                    }
                });
            }

            var location = config.authorizationURL + '?' + querystring.stringify(params);
            self.redirect(location);
        });
    }
};

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
Strategy.prototype.configure = function (identifier, done) {
    if (typeof identifier === 'function') {
        return this._configurers.push(identifier);
    }

    // private implementation that traverses the chain of configurers, attempting
    // to load configuration
    var stack = this._configurers;
    (function pass(i, err, config) {
        // an error or configuration was obtained, done
        if (err || config) {
            return done(err, config);
        }

        var layer = stack[i];
        if (!layer) {
            // Strategy-specific functions did not result in obtaining configuration
            // details.  Proceed to protocol-defined mechanisms in an attempt
            // to discover the provider's configuration.
            return setup(identifier, done);
        }

        try {
            layer(identifier, function (e, c) {
                pass(i + 1, e, c);
            })
        } catch (ex) {
            return done(ex);
        }
    })(0);
};


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
Strategy.prototype.authorizationParams = function (req, options) {
    var params = {
        state: encodeURIComponent(utils.uid(16))
    };
    if (this._generateNonce) {
        params.nonce = encodeURIComponent(utils.uid(16))
    }
    return params;
};

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
