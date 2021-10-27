# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added

- Added `customHeaders` option to `Strategy` constructor, matching functionality
in `passport-oauth2`.
- Added `proxy` option to `Strategy` constructor, which can be set to `true` to
indicate the app is behind a front-facing proxy.  Used when resolving relative
redirect URIs to an absolute URI.
- Added `agent` option to `Strategy` constructor, used to control `http.Agent`
behavior.
- Support for `StateStore#store()` function signature which accepts
application-supplied state as an argument.
- Support for `state` object passed as option to `authenticate`, which will be
persisted in the session by state store.
- Parsing `profile.username` from UserInfo response.
- Parsing `profile.emails` from UserInfo response.

### Changed

- `display` option can now take any value, rather than just defined values, in
order to support values defined by extensions.

### Removed

- Removed `params` property, which contained all authentication request
parameters, from state stored in session.  Most of these parameters are not
required to validate the authentication response and this minimizes the size of
session data.

### Fixed

- Corrected `ui_locales` option to Strategy constructor.  Was previously
misspelled as `ui_locals`.
- Correctly validating that an `azp` claim is present if the ID token contains
multiple audiences.

## [0.0.2] - 2017-02-23

## [0.0.1] - 2013-02-16

- Initial release.

[Unreleased]: https://github.com/jaredhanson/passport-openidconnect/compare/v0.0.2...HEAD
[0.0.2]: https://github.com/jaredhanson/passport-openidconnect/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/jaredhanson/passport-openidconnect/releases/tag/v0.0.1
