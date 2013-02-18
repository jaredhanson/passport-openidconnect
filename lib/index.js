/**
 * Module dependencies.
 */
var Strategy = require('./strategy')
  , discovery = require('./discovery')


/**
 * Framework version.
 */
require('pkginfo')(module, 'version');

/**
 * Expose constructors.
 */
exports.Strategy = Strategy;
exports.discovery = discovery;

discovery.disco(require('./discover/webfinger')());