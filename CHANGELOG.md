# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2021-11-29
### Added
- Support for `prompt` option to `authenticate()`.

## [0.1.0] - 2021-11-17
### Added

- Parsing `profile.username` from standard claims.
- Parsing `profile.emails` from standard claims.
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
- 5-arity form of `verify` function invoked with (`iss`, `profile`, `context`
`idToken`, `cb`) arguments.
- 9-arity form of `verify` function invoked with (`iss`, `uiProfile`,
`idProfile`, `context`, `idToken`, `accessToken`, `refreshToken`, `params`,
`cb`) arguments.
- Added `maxAge` and `nonce` properties to state stored in session.
- Added `issued` property to state stored in session, only when `maxAge` option
is used.
- Parsing of errors from token endpoint.

### Changed

- By default, profile is parsed from ID token and UserInfo is not fetched,
optimizing for network latency.
- The 3-arity form of `verify` function now invoked with (`iss`, `profile`,
`cb`) arguments, rather than (`iss`, `sub`, `cb`).
- The 4-arity form of `verify` function now invoked with (`iss`, `profile`,
`context`, `cb`) arguments, rather than (`iss`, `sub`, `profile`, `cb`).
- The 7-arity form of `verify` function now invoked with (`iss`, `profile`,
`context`, `idToken`, `accessToken`, `refreshToken`, `cb`) arguments, rather
than (`iss`, `sub`, `profile`, `accessToken`, `refreshToken`, `params`, `cb`).
- The 8-arity form of `verify` function now invoked with (`iss`, `profile`,
`context`, `idToken`, `accessToken`, `refreshToken`, `params`, `cb`)
arguments, rather than (`iss`, `sub`, `profile`, `claims`, `accessToken`,
`refreshToken`, `params`, `cb`).
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
- `skipUserProfile` option, when set to a function, is now invoked with `req`,
`claims` arguments, rather than `iss`, `sub`.
- Switched to using `OAuth2#get`, from `OAuth2#_request`, when making UserInfo
request.  As a result, `Accept: 'application/json` header no longer sent.  This
header isn't needed, per spec.

### Removed

- Removed support for OpenID Connect Discovery and Dynamic Registration, as it
is largely unused and the functionality would be better suited in a different
package.
- Removed the `schema=openid` parameter when making a request to the UserInfo
endpoint.  The last draft specification to include this was [24](https://openid.net/specs/openid-connect-basic-1_0-24.html).
- Removed capability to pass `nonce` option as string or number values.
- Removed the 6-arity form of `verify` function which was invoked with (`iss`,
`sub`, `profile`, `accessToken`, `refreshToken`, `cb`) arguments.
- Removed `issuer`, `authorizationURL`, `tokenURL`, `userInfoURL`, `clientID`,
and `callbackURL` from state stored in session.  This information is redundant as
state is stored with a key derived from the issuer.
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

[Unreleased]: https://github.com/jaredhanson/passport-openidconnect/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/jaredhanson/passport-openidconnect/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/jaredhanson/passport-openidconnect/compare/v0.0.2...v0.1.0
[0.0.2]: https://github.com/jaredhanson/passport-openidconnect/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/jaredhanson/passport-openidconnect/releases/tag/v0.0.1
