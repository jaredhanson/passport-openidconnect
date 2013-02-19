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

exports.config = function(fn) {
  setup.configuration(fn);
}

/**
 * Expose discovery mechanisms.
 */
exports.discovery = {};
exports.discovery.webfinger = require('./discovery/webfinger');
exports.discovery.lrdd = require('./discovery/lrdd');

exports.disco(require('./discovery/webfinger')());
