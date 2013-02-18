/**
 * Module dependencies.
 */
var Strategy = require('./strategy')
  , setup = require('./setup')


/**
 * Framework version.
 */
require('pkginfo')(module, 'version');

/**
 * Expose constructors.
 */
exports.Strategy = Strategy;

/**
 * Export configuration functions.
 */
exports.disco = function(fn) {
  setup.discovery(fn);
}

/**
 * Expose discovery mechanisms.
 */
exports.discovery = {};
exports.discovery.webfinger = require('./discover/webfinger');
exports.discovery.lrdd = require('./discover/lrdd');

exports.disco(require('./discover/webfinger')());
//discovery.disco(require('./discover/lrdd')());
