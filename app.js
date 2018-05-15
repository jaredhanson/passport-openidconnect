var express = require('express')
  , passport = require('passport')
  , util = require('util')
  , OpenIDStrategy = require('./lib/index').Strategy;

var https = require('https');
var http = require('http');
var fs = require('fs');

// Passport session setup.
//   To support persistent login sessions, Passport needs to be able to
//   serialize users into and deserialize users out of the session.  Typically,
//   this will be as simple as storing the user ID when serializing, and finding
//   the user by ID when deserializing.  However, since this example does not
//   have a database of user records, the OpenID identifier is serialized and
//   deserialized.
passport.serializeUser(function(user, done) {
  done(null, user.profile);
});

passport.deserializeUser(function(identifier, done) {
  done(null, { identifier: identifier });
});


// Use the OpenIDStrategy within Passport.
//   Strategies in passport require a `validate` function, which accept
//   credentials (in this case, an OpenID identifier), and invoke a callback
//   with a user object.
passport.use(new OpenIDStrategy({
    callbackURL: 'http://localhost:3000/auth/openid/return',
    returnURL: 'http://localhost:3000/auth/openid/return',
    realm: 'http://localhost:3000/',
    authorizationURL: 'https://apiary.identity.preprod.oraclecloud.com/oauth2/v1/authorize',
    getClientCallback: 'https://apiary.identity.preprod.oraclecloud.com/',
    clientID: '4ecea1bad66f421d8602df7e896fec47',
    clientSecret: '708c050e-251a-4e72-9d8b-34001a3da45a',
    tokenURL: 'https://apiary.identity.preprod.oraclecloud.com/oauth2/v1/token',
    issuer: 'https://identity.oraclecloud.com/',
    userInfoURL: 'https://apiary.identity.preprod.oraclecloud.com/oauth2/v1/userinfo',
    passReqToCallback: true
  },
  function(req, iss, sub, profile, jwtClaims, accessToken, refreshToken, params, done) {
    console.error('----------iss, sub, profile, jwtClaims, accessToken, refreshToken, params-----------');
    console.error({
      iss,
      sub,
      profile,
      jwtClaims,
      accessToken,
      refreshToken,
      params
    });
    console.error(done);

    return done(null, { profile: profile })

  }
));


var cookieParser = require('cookie-parser');
var methodOverride = require('method-override');
var session = require('express-session');
var bodyParser = require('body-parser');

var app = express();
//Middleware

// configure Express

  app.set('views', __dirname + '/views');
  app.set('view engine', 'ejs');
  app.use(cookieParser());
  app.use(bodyParser());
  app.use(methodOverride());
  app.use(session({ secret: 'keyboard cat' }));
  // Initialize Passport!  Also use passport.session() middleware, to support
  // persistent login sessions (recommended).
  app.use(passport.initialize());
  app.use(passport.session());
  app.use(express.static(__dirname + '/../../public'));


app.get('/', function(req, res){
  res.render('index', { user: req.user });
});

app.get('/account', ensureAuthenticated, function(req, res){
  res.render('account', { user: req.user });
});

app.get('/login', function(req, res){
  res.render('login', { user: req.user });
});

// POST /auth/openid
//   Use passport.authenticate() as route middleware to authenticate the
//   request.  The first step in OpenID authentication will involve redirecting
//   the user to their OpenID provider.  After authenticating, the OpenID
//   provider will redirect the user back to this application at
//   /auth/openid/return
app.post('/auth/openid',
  passport.authenticate('openidconnect', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect('/');
  });

// GET /auth/openid/return
//   Use passport.authenticate() as route middleware to authenticate the
//   request.  If authentication fails, the user will be redirected back to the
//   login page.  Otherwise, the primary route function function will be called,
//   which, in this example, will redirect the user to the home page.
app.get('/auth/openid/return',
  passport.authenticate('openidconnect', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect('/');
  });

app.get('/logout', function(req, res){
  req.logout();
  res.redirect('/');
});

https.createServer({
  key: fs.readFileSync('./key.pem'),
  cert: fs.readFileSync('./cert.pem'),
  passphrase: 'towdie'
}, app).listen(3003);
http.createServer(app).listen(3000);

// Simple route middleware to ensure user is authenticated.
//   Use this route middleware on any resource that needs to be protected.  If
//   the request is authenticated (typically via a persistent login session),
//   the request will proceed.  Otherwise, the user will be redirected to the
//   login page.
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) { return next(); }
  res.redirect('/login')
}
