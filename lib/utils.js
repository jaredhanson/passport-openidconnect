var crypto = require('crypto');
var querystring= require('querystring')

/**
 * Reconstructs the original URL of the request.
 *
 * This function builds a URL that corresponds the original URL requested by the
 * client, including the protocol (http or https) and host.
 *
 * If the request passed through any proxies that terminate SSL, the
 * `X-Forwarded-Proto` header is used to detect if the request was encrypted to
 * the proxy.
 *
 * @return {String}
 * @api private
 */
exports.originalURL = function(req, options) {
  options = options || {};
  var app = req.app;
  if (app && app.get && app.get('trust proxy')) {
    options.proxy = true;
  }
  var trustProxy = options.proxy;
  
  var proto = (req.headers['x-forwarded-proto'] || '').toLowerCase()
    , tls = req.connection.encrypted || (trustProxy && 'https' == proto.split(/\s*,\s*/)[0])
    , host = (trustProxy && req.headers['x-forwarded-host']) || req.headers.host
    , protocol = tls ? 'https' : 'http'
    , path = req.url || '';
  return protocol + '://' + host + path;
};

/**
 * Merge object b with object a.
 *
 *     var a = { foo: 'bar' }
 *       , b = { bar: 'baz' };
 *     
 *     utils.merge(a, b);
 *     // => { foo: 'bar', bar: 'baz' }
 *
 * @param {Object} a
 * @param {Object} b
 * @return {Object}
 * @api private
 */

exports.merge = function(a, b){
  if (a && b) {
    for (var key in b) {
      a[key] = b[key];
    }
  }
  return a;
};

/**
 * Return a unique identifier with the given `len`.
 *
 *     utils.uid(10);
 *     // => "FDaS435D2z"
 *
 * CREDIT: Connect -- utils.uid
 *         https://github.com/senchalabs/connect/blob/2.7.2/lib/utils.js
 *
 * @param {Number} len
 * @return {String}
 * @api private
 */

exports.uid = function(len) {
  return crypto.randomBytes(Math.ceil(len * 3 / 4))
    .toString('base64')
    .slice(0, len);
};

/**
 * Override getOAuthAccessToken to use an Authorization header instead of sending
 * client_id and client_secret in the url
 */
exports.fixOAuthLib = function(lib) {
  lib.prototype.getOAuthAccessToken = function(code, params, callback, useAuthorization) {
    var useAuthorization = useAuthorization || false;

    var params= params || {};
    var codeParam = (params.grant_type === 'refresh_token') ? 'refresh_token' : 'code';
    params[codeParam]= code;
  
    var post_data= querystring.stringify( params );
    var post_headers= {
      'Content-Type': 'application/x-www-form-urlencoded'
    };

    if(useAuthorization) {
      post_headers['Authorization'] = 'Basic ' + new Buffer(this._clientId + ':' + this._clientSecret).toString('base64')
    }
    else {
      params['client_id'] = this._clientId;
      params['client_secret'] = this._clientSecret;
    }
  
    this._request("POST", this._getAccessTokenUrl(), post_headers, post_data, null, function(error, data, response) {
      if( error )  callback(error);
      else {
        var results;
        try {
          // As of http://tools.ietf.org/html/draft-ietf-oauth-v2-07
          // responses should be in JSON
          results= JSON.parse( data );
        }
        catch(e) {
          // .... However both Facebook + Github currently use rev05 of the spec
          // and neither seem to specify a content-type correctly in their response headers :(
          // clients of these services will suffer a *minor* performance cost of the exception
          // being thrown
          results= querystring.parse( data );
        }
        var access_token= results["access_token"];
        var refresh_token= results["refresh_token"];
        delete results["refresh_token"];
        callback(null, access_token, refresh_token, results); // callback results =-=
      }
    });
  }
  return lib;
}