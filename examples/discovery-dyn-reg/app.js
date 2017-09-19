var express = require('express');
var http = require('http');
var path = require('path');
var partials = require('express-partials');
var passport = require('passport');
var OpenidConnectStrategy = require('../../lib').Strategy;

var PORT = process.env.PORT || 80;

var RP_DOMAIN_NAME = 'localhost:' + PORT;

var CLIENT_NAME = 'AiryDrive - test2';
var CALLBACK_URL = '/auth/oidc/callback';
var REDIRECT_URIS = ['http://' + RP_DOMAIN_NAME + CALLBACK_URL];
var SCOPE = 'profile email';

// Configuration database with oidc and user tables
var Config = {oidc: [], user: []};

function removeTrailingSlashes(str)
{
  return str.replace(/\/+$/, "");
}

passport.serializeUser(function(user, done) {
    done(null, user);
});

passport.deserializeUser(function(user, done) {
    done(null, user);
});

function userFindOrCreate(issuer, sub, userInfo, provider, done) {
  var email = userInfo && userInfo.email ? userInfo.email : null;
  if (email) {
    findUserByEmail(email, function(issuer, userInfo, err, user) {
      if (!user) {
        var user_id = Config.user.length + 1;
        user = {id: user_id, oidc_id: null, sub: userInfo.sub, email: email, displayName: userInfo.displayName};
        Config.user.push(user);
      }
      findOidcByIssuer(issuer, function(user, err, oidc) {
        if (oidc) {
          user.oidc_id = oidc.id;
          done(null, user);
        } else {
          done('Cannot select oidc configuration', user);
        }
      }.bind(this, user));
    }.bind(this, issuer, userInfo));
  } else {
    done('Cannot select user', null);
  }
}

function findOidcById(id, fn) {
  for (var i = 0, len = Config.oidc.length; i < len; i++) {
    var oidc = Config.oidc[i];
    if (oidc.id === id) {
      return fn(null, oidc);
    }
  }
  return fn(null, null);
}

function findOidcByIssuer(iss, fn) {
  for (var i = 0, len = Config.oidc.length; i < len; i++) {
    var oidc = Config.oidc[i];
    if (removeTrailingSlashes(oidc.provider.issuer) === removeTrailingSlashes(iss)) {
      return fn(null, oidc);
    }
  }
  return fn(null, null);
}

function findUserByEmail(email, fn) {
  for (var i = 0, len = Config.user.length; i < len; i++) {
    var user = Config.user[i];
    if (user.email === email) {
      return fn(null, user);
    }
  }
  return fn(null, null);
}

function saveConfig(provider, reg, next) {
  var oidc_id = Config.oidc.length + 1;
  Config.oidc.push({id: oidc_id, provider: provider, reg: reg});
  return next();
};

function loadConfigByIssuer(issuer, done) {
  findOidcByIssuer(issuer, function(err, oidc) {
    if (oidc) {
      return done(null, {
        authorizationURL: oidc.provider.authorizationURL,
        tokenURL: oidc.provider.tokenURL,
        userInfoURL: oidc.provider.userInfoURL,
        clientID: oidc.provider.clientID,
        clientSecret: oidc.reg.clientSecret,
        callbackURL: CALLBACK_URL
      });
    } else {
      return done(err, null);
    }
  });

};

function loadConfigByIdentifier(identifier, done) {
  findUserByEmail(identifier, function(err, user) {
    if (user) {
      if (user.oidc_id) {
        findOidcById(user.oidc_id, function(err, oidc) {
          if (oidc) {
            return done(err, {
              authorizationURL: oidc.provider.authorizationURL,
              tokenURL: oidc.provider.tokenURL,
              userInfoURL: oidc.provider.userInfoURL,
              clientID: oidc.provider.clientID,
              clientSecret: oidc.reg.clientSecret,
              callbackURL: CALLBACK_URL
            });
          } else {
            return done('Cannot select oidc configuration', null);
          }
        });
      } else {
        return done(err, null);
      }
    } else {
      return done(err, null);
    }
  })
};

var strategy = new OpenidConnectStrategy({
  identifierField: 'emailField',
  sessionKey: 'fubar',
  getClientCallback: function (issuer, cb) { cb(null, null); },
  scope: SCOPE,
  clientMetadata: {
    client_name: CLIENT_NAME,
    redirect_uris: REDIRECT_URIS
  }
},
  function(iss, sub, userInfo, accessToken, refreshToken, done) {
    process.nextTick(function () {

      // find or create the user based on their email address
      userFindOrCreate(iss, sub, userInfo, 'openidconnect', function(err, user) {
        if (err)
          console.log(err);
        done(err, user);
      });

    });
  }
);

passport.use(strategy);

var app = express();

// all environments
app.set('port', PORT);
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.use(partials());
app.use(express.logger('dev'));
app.use(express.json());
app.use(express.urlencoded());
app.use(express.methodOverride());
app.use(express.cookieParser('your secret here'));
app.use(express.session());
// Initialize Passport!  Also use passport.session() middleware, to support
// persistent login sessions (recommended).
app.use(passport.initialize());
app.use(passport.session());
app.use(app.router);
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.errorHandler());

app.get('/', function(req, res){
  res.render('index', { user: req.user });
});

app.get('/account', ensureAuthenticated, function(req, res){
  res.render('account', { user: req.user });
});

app.get('/login', function(req, res){
  res.render('login', { user: req.user });
});

app.get('/auth/oidc/login', passport.authenticate('openidconnect',
  { callbackURL: CALLBACK_URL, failureRedirect: '/login' }),
  function (req, res) {
    // The request will be redirected to OP for authentication, so this
    // function will not be called.
});

app.get(CALLBACK_URL, passport.authenticate('openidconnect',
  {callbackURL: CALLBACK_URL, failureRedirect: '/login'}),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/');
});

app.get('/logout', function(req, res){
  req.logout();
  res.redirect('/');
});

http.createServer(app).listen(app.get('port'), function(){
  console.log('Express server listening on port ' + app.get('port'));
});

// Simple route middleware to ensure user is authenticated.
//   Use this route middleware on any resource that needs to be protected.  If
//   the request is authenticated (typically via a persistent login session),
//   the request will proceed.  Otherwise, the user will be redirected to the
//   login page.
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) { return next(); }
  res.redirect('/login');
}
