var utils = require('../utils');

/**
 * Creates an instance of `SessionStore`.
 *
 * This is the state store implementation for the OIDCStrategy used when
 * the `state` option is enabled.  It generates a random state and stores it in
 * `req.session` and verifies it when the service provider redirects the user
 * back to the application.
 *
 * This state store requires session support.  If no session exists, an error
 * will be thrown.
 *
 * Options:
 *
 *   - `key`  The key in the session under which to store the state
 *
 * @constructor
 * @param {Object} options
 * @api public
 */
function SessionStore(options) {
  if (!options.key) { throw new TypeError('Session-based state store requires a session key'); }
  this._key = options.key;
}

/**
 * Store request state.
 *
 * This implementation simply generates a random string and stores the value in
 * the session, where it will be used for verification when the user is
 * redirected back to the application.
 *
 * @param {Object} req
 * @param {Function} cb
 * @api protected
 */
SessionStore.prototype.store = function(req, ctx, appState, meta, cb) {
  if (!req.session) { return cb(new Error('OpenID Connect requires session support. Did you forget to use `express-session` middleware?')); }

  var key = this._key;
  var handle = utils.uid(24);

  var state = { handle: handle };
  if (ctx.maxAge) { state.maxAge = ctx.maxAge; }
  if (ctx.nonce) { state.nonce = ctx.nonce; }
  if (ctx.issued) { state.issued = ctx.issued; }
  if (appState) { state.state = appState; }

  if (!req.session[key]) { req.session[key] = {}; }
  req.session[key].state = state;

  cb(null, handle);
};

/**
 * Verify request state.
 *
 * This implementation simply compares the state parameter in the request to the
 * value generated earlier and stored in the session.
 *
 * @param {Object} req
 * @param {String} providedState
 * @param {Function} cb
 * @api protected
 */
SessionStore.prototype.verify = function(req, handle, cb) {
  if (!req.session) { return cb(new Error('OpenID Connect requires session support. Did you forget to use `express-session` middleware?')); }

  var key = this._key;
  if (!req.session[key]) {
   return cb(null, false, { message: 'Unable to verify authorization request state.' });
  }

  var state = req.session[key].state;
  if (!state) {
   return cb(null, false, { message: 'Unable to verify authorization request state.' });
  }

  delete req.session[key].state;
  if (Object.keys(req.session[key]).length === 0) {
   delete req.session[key];
  }

  if (state.handle !== handle) {
   return cb(null, false, { message: 'Invalid authorization request state.' });
  }
  
  var ctx = {
    maxAge: state.maxAge,
    nonce: state.nonce,
    issued: state.issued
  };
  if (typeof ctx.issued === 'string') {
    // convert issued to a Date object
    ctx.issued = new Date(ctx.issued);
  }

  return cb(null, ctx, state.state);
};

// Expose constructor.
module.exports = SessionStore;
