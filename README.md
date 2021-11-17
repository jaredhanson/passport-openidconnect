# passport-openidconnect

[Passport](https://www.passportjs.org/) strategy for authenticating
with [OpenID Connect](https://openid.net/connect/).

This module lets you authenticate using OpenID Connect in your Node.js
applications.  By plugging into Passport, OpenID Connect authentication can be
easily and unobtrusively integrated into any application or framework that
supports [Connect](https://github.com/senchalabs/connect#readme)-style
middleware, including [Express](https://expressjs.com/).

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

```js
var OpenIDConnectStrategy = require('passport-openidconnect');

passport.use(new OpenIDConnectStrategy({
    issuer: 'https://server.example.com',
    authorizationURL: 'https://server.example.com/authorize',
    tokenURL: 'https://server.example.com/token',
    clientID: 's6BhdRkqt3',
    clientSecret: 'some_secret12345',
    callbackURL: 'https://client.example.org/cb'
  },
  function verify(issuer, profile, cb) {
    db.get('SELECT * FROM federated_credentials WHERE provider = ? AND subject = ?', [
      issuer,
      profile.id
    ], function(err, cred) {
      if (err) { return cb(err); }
      if (!cred) {
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
              id: id.toString(),
              displayName: profile.displayName
            };
            return cb(null, user);
          });
        });
      } else {
        db.get('SELECT * FROM users WHERE id = ?', [ cred.user_id ], function(err, user) {
          if (err) { return cb(err); }
          if (!user) { return cb(null, false); }
          return cb(null, user);
        });
      }
    }
  })
));
```


## License

[The MIT License](https://opensource.org/licenses/MIT)

Copyright (c) 2011-2021 Jared Hanson <[https://www.jaredhanson.me/](https://www.jaredhanson.me/)>

