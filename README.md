# Passport-OpenID Connect

[Passport](https://github.com/jaredhanson/passport) strategy for authenticating
with [OpenID Connect](http://openid.net/connect/).

This module lets you authenticate using OpenID Connect in your Node.js
applications.  By plugging into Passport, OpenID Connect authentication can be
easily and unobtrusively integrated into any application or framework that
supports [Connect](http://www.senchalabs.org/connect/)-style middleware,
including [Express](http://expressjs.com/).


## Dynamic flow

If you don't provide `authorizationURL` and `tokenURL` in the strategy options,
it is assumed that you want the OpenID Dynamic flow with automatic
[Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html) and/or
[Registration](https://openid.net/specs/openid-connect-registration-1_0.html).

The default Registrar module will use the following options:


* `clientMetadata` (REQUIRED) - Information about your client, as an object, with the keys
  described in
  [Client Metadata](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata).
  Note that `redirect_uris` is REQUIRED.

* `getClientCallback` (REQUIRED) - `function(issuer, cb)`: call the `cb` function with
  `(err, client)`.  `issuer` is the OpenID Connect provider,
  e.g. `https://example.com`.  If you don't have a client for that issuer, use
  `cb(null, null)` to commence registration.  If you have on, return it in the
  following form `cb(null, client)`, where client is an object with:

  * `id` (REQUIRED)
  * `secret` (OPTIONAL, as given from provider)
  * `secretExpiresAt` (OPTIONAL, as given from provider)

* `saveClientCallback` (OPTIONAL) - `function(client, cb)`: Called when a new client is
  registered, with the client object as above.  When done, pass the client on
  to the callback: `cb(null, client)`.


## Credits

  - [Jared Hanson](http://github.com/jaredhanson)

## License

[The MIT License](http://opensource.org/licenses/MIT)

Copyright (c) 2011-2013 Jared Hanson <[http://jaredhanson.net/](http://jaredhanson.net/)>
