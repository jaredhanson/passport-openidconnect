# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added

- Parsing `profile.username` from UserInfo response.
- Parsing `profile.emails` from UserInfo response.
- Support for `loginHint` options to `authenticate()`.
- Support for `state` object passed as option to `authenticate`, which will be
persisted in the session by state store.
- Support for `responseMode` options to `Strategy` constructor.
- Support for `claims` options to `Strategy` constructor.
- Added `customHeaders` option to `Strategy` constructor, matching functionality
in `passport-oauth2`.
- Added `proxy` option to `Strategy` constructor, which can be set to `true` to
indicate the app is behind a front-facing proxy.  Used when resolving relative
redirect URIs to an absolute URI.
- Added `agent` option to `Strategy` constructor, used to control `http.Agent`
behavior.
- Added `maxAge` and `nonce` properties to state stored in session.
- Added `issued` property to state stored in session, only when `maxAge` option
is used.

### Changed

- `prompt` option can now take any value, rather than just defined values, in
order to support values defined by extensions.
- `display` option can now take any value, rather than just defined values, in
order to support values defined by extensions.
- `ui_locals` option to `Strategy` constructor renamed to `uiLocales`.
- `login_hint` option to `Strategy` constructor renamed to `loginHint`.
- `max_age` option to `Strategy` constructor renamed to `maxAge`.
- `acr_values` option to `Strategy` constructor renamed to `acrValues`.
- `id_token_hint` option to `Strategy` constructor renamed to `idTokenHint`.
- `Strategy` constructor no longer requires a `clientSecret` option.
- `info.state` supplied to `success()` action contains only app-level state, no
longer contains state internal to the strategy (`handle`, etc).
- Treat invalid `iss` claim as an authentication failure rather than an error.
- Treat invalid `aud` claim as an authentication failure rather than an error.
- Treat invalid `azp` claim as an authentication failure rather than an error.
- Treat expired `exp` claim as an authentication failure rather than an error.
- Treat invalid `nonce` claim as an authentication failure rather than an error.
- `StateStore#store()` function signature now only supports single variation
with arguments (`req`, `ctx`, `state`, `meta`, `cb`), as opposed to previous
four, three, and two argument variations.
- Callback passed to `StateStore#store()` now expected to be involved with
`(err, ctx, state)`, rather than `(err, ok, state)`, where `ctx` is an object,
rather than a boolean, and contains the protocol context needed to validate the
authentication response.

### Removed

- Removed support for OpenID Connect Discovery and Dynamic Registration, as it
is largely unused and the functionality would be better suited in a different
package.
- Removed capability to pass `nonce` option as string or number values.
- Removed `authorizationURL`, `tokenURL`, `userInfoURL`, `clientID`, and
`callbackURL` from state stored in session.  This information is redundant and
can be derived from `issuer`, which remains in the session.
- Removed `clientSecret` property from state stored in session.
- Removed `params` property, which contained all authentication request
parameters, from state stored in session.  Most of these parameters are not
required to validate the authentication response and this minimizes the size of
session data.
- Removed `timestamp` property from state stored in session.

### Fixed

- Correctly validating that an `azp` claim is present if the ID token contains
multiple audiences.
- ID token expiration check is inclusive of the current time.

## [0.0.2] - 2017-02-23

## [0.0.1] - 2013-02-16

- Initial release.

[Unreleased]: https://github.com/jaredhanson/passport-openidconnect/compare/v0.0.2...HEAD
[0.0.2]: https://github.com/jaredhanson/passport-openidconnect/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/jaredhanson/passport-openidconnect/releases/tag/v0.0.1
