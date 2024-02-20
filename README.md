# passport-openidconnect

[Passport](https://www.passportjs.org/) strategy for authenticating
with [OpenID Connect](https://openid.net/connect/).

This module lets you authenticate using OpenID Connect in your Node.js
applications.  By plugging into Passport, OpenID Connect-based sign in can be
easily and unobtrusively integrated into any application or framework that
supports [Connect](https://github.com/senchalabs/connect#readme)-style
middleware, including [Express](https://expressjs.com/).

<div align="center">

:heart: [Sponsors](https://www.passportjs.org/sponsors/?utm_source=github&utm_medium=referral&utm_campaign=passport-openidconnect&utm_content=nav-sponsors)

</div>

## Install

```sh
$ npm install passport-openidconnect
```

## Usage

#### Configure Strategy

The OpenID Connect authentication strategy authenticates users using their
account at an OpenID Provider (OP).  The strategy needs to be configured with
the provider's endpoints, as well as a client ID and secret that has been issued
by the provider to the app.  Consult the provider's documentation for the
locations of these endpoints and instructions on how to register a client.

The strategy takes a `verify` function as an argument, which accepts `issuer`
and `profile` as arguments.  `issuer` is set to an identifier for the OP.
`profile` contains the user's [profile information](https://www.passportjs.org/reference/normalized-profile/)
stored in their account at the OP.  When authenticating a user, this strategy
uses the OpenID Connect protocol to obtain this information via a sequence of
redirects and back-channel HTTP requests to the OP.

The `verify` function is responsible for determining the user to which the
account at the OP belongs.  In cases where the account is logging in for the
first time, a new user record is typically created automatically.  On subsequent
logins, the existing user record will be found via its relation to the OP
account.

Because the `verify` function is supplied by the application, the app is free to
use any database of its choosing.  The example below illustrates usage of a SQL
database.

```js
var OpenIDConnectStrategy = require('passport-openidconnect');

passport.use(new OpenIDConnectStrategy({
    issuer: 'https://server.example.com',
    authorizationURL: 'https://server.example.com/authorize',
    tokenURL: 'https://server.example.com/token',
    userInfoURL: 'https://server.example.com/userinfo',
    clientID: process.env['CLIENT_ID'],
    clientSecret: process.env['CLIENT_SECRET'],
    callbackURL: 'https://client.example.org/cb',
    scope: [ 'profile' ]
  },
  function verify(issuer, profile, cb) {
    db.get('SELECT * FROM federated_credentials WHERE provider = ? AND subject = ?', [
      issuer,
      profile.id
    ], function(err, cred) {
      if (err) { return cb(err); }
      
      if (!cred) {
        // The account at the OpenID Provider (OP) has not logged in to this app
        // before.  Create a new user account and associate it with the account
        // at the OP.
        db.run('INSERT INTO users (name) VALUES (?)', [
          profile.displayName
        ], function(err) {
          if (err) { return cb(err); }
          
          var id = this.lastID;
          db.run('INSERT INTO federated_credentials (user_id, provider, subject) VALUES (?, ?, ?)', [
            id,
            issuer,
            profile.id
          ], function(err) {
            if (err) { return cb(err); }
            var user = {
              id: id,
              name: profile.displayName
            };
            return cb(null, user);
          });
        });
      } else {
        // The account at the OpenID Provider (OP) has previously logged in to
        // the app.  Get the user account associated with the account at the OP
        // and log the user in.
        db.get('SELECT * FROM users WHERE id = ?', [ cred.user_id ], function(err, row) {
          if (err) { return cb(err); }
          if (!row) { return cb(null, false); }
          return cb(null, row);
        });
      }
    });
  }
));
```

#### Define Routes

Two routes are needed in order to allow users to log in with their account at an
OP.  The first route redirects the user to the OP, where they will authenticate:

```js
app.get('/login', passport.authenticate('openidconnect'));
```

The second route processes the authentication response and logs the user in,
when the OP redirects the user back to the app:

```js
app.get('/cb',
  passport.authenticate('openidconnect', { failureRedirect: '/login', failureMessage: true }),
  function(req, res) {
    res.redirect('/');
  });
```

## Examples

* [todos-express-openidconnect](https://github.com/passport/todos-express-openidconnect)

  Illustrates how to use the OpenID Connect strategy within an Express
  application.

* [todos-express-auth0](https://github.com/passport/todos-express-auth0)

  Illustrates how to use the OpenID Connect strategy to integrate with [Auth0](https://auth0.com/)
  in an Express application.  For developers new to Passport and getting
  started, a [tutorial](https://www.passportjs.org/tutorials/auth0/) is
  available.

## License

[The MIT License](https://opensource.org/licenses/MIT)

Copyright (c) 2011-2022 Jared Hanson <[https://www.jaredhanson.me/](https://www.jaredhanson.me/)>
