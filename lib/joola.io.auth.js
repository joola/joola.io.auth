var logger = require('joola.io.logger');

var component_name = global.logger_component || 'auth';

var notAllowed = function (err, prettymessage, req, res) {
  if (err) {
    var message = 'Authentication failed [' + req.connection.remoteAddress + ']:' + err;
    logger.warn(message, {component: component_name});
  }
  res.status(401);
  return expireSession(req, function () {
    return res.json({result: 'not allowed'});
  });
};

var redirectLogin = function (err, prettymessage, req, res) {
  if (err) {
    var message = 'Authentication failed [' + req.connection.remoteAddress + ']:' + err;
    logger.warn(message, {component: component_name});
  }
  return expireSession(req, function () {
    return res.render(__dirname + '/../views/login', {reason: prettymessage});
  });
};

var Allowed = function (reason, req, res, next) {
  logger.debug('Authentication success [' + reason + ']:[' + req.connection.remoteAddress + ']:[' + req.url + ']:[' + (req.token ? req.token : 'n/a') + ']:[' + req.session.user.username + ']', {component: component_name});

  if (req.session)
    touchSession(req, function () {
    });

  if (req.url.substring(0, 6) == '/login' && req.query.redirect)
    return res.redirect(req.query.redirect);
  else if (req.url.substring(0, 6) == '/login' && !req.query.redirect)
    return res.redirect('/');
  else
    return next();
};

var createSession = function (session, callback) {
  session.created = new Date();
  session.updated = new Date();
  return callback(null);
};

var expireSession = function (req, callback) {
  req.user = null;
  if (req.session)
    req.session.destroy(function () {
      return callback(null);
    });
  else
    return callback(null);
};

var touchSession = function (req, callback) {
  req.session.updated = new Date();
  var timeoutID = req.session.timeoutID;
  if (timeoutID)
    clearTimeout(timeoutID);

  /*
   timeoutID = setTimeout(function () {
   return sessionExpired(req.session.token, function () {
   });
   }, req.session.cookie.maxAge - 1000);
   req.session.timeoutID = timeoutID;
   */
  return callback(null);
};

var sessionExpired = function (token, callback) {
  joola.logger.debug('Session expired, token: ' + token);
  return callback(null);
};

var isAllowedCOntent = function (req) {
  if (req.method == 'OPTIONS')
    return true;

  //allow assets without auth
  if (req.url.substring(0, 7) == '/assets' || req.url.substring(0, 5) == '/auth')
    return true;

  return false;
};

var isLogout = function (req) {
  if (req.url.substring(0, 7) == '/logout')
    return true;

  return false;
};

// the middleware function
module.exports = function (options) {
  return function (req, res, next) {
    if (isAllowedCOntent(req))
      return next();

    if (isLogout(req)) {
      return expireSession(req, function () {
        //res.clearCookie('connect.sid', { path: '/' });
        return redirectLogin(null, null, req, res);
      });
    }

    //anonymous auth is a easy bypass
    if (options.anonymous) {
      var user = {
        username: 'Anonymous'
      };
      req.user = user;
      req.session.user = user;
      return Allowed('anonymous', req, res, next);
    }

    //check we have a valid session for this user
    if (options.sessions) {
      if (req.session) {
        if (req.session.user) {
          req.query.token = req.session.token
        }
      }
    }

    if (req.headers['joola-token'])
      req.query.token = req.headers['joola-token'];

    if (req.body.username)
      req.query.username = req.body.username;
    if (req.body.password)
      req.query.password = req.body.password;
    if (req.body.redirect)
      req.query.redirect = req.body.redirect;

    logger.silly('Request for Authentication [' + req.url + ']:[' + req.connection.remoteAddress + ']:[' + (req.query.token ? req.query.token : 'n/a') + ']', {component: component_name});
    //check whitelist for inclusion of ip (if enabled)
    if (options.whitelist && options.whitelist.length > 0)
      if (options.whitelist.indexOf(req.connection.remoteAddress) == -1)
        return redirectLogin('Not Allowed [2]', 'Username/password not found.', req, res);


    //token checks
    if (req.query.token) {
      req.token = req.query.token;
      req.session.token = req.token;

      //first, bypass token
      if (options.bypassToken) {
        if (options.bypassToken == req.query.token) {
          var user = {
            username: 'Bypass Token'
          };
          req.session.user = user;
          return Allowed('bypass', req, res, next);
        }
      }

      var getter = (options.endpoint.secure ? require('https') : require('http'));

      var hoptions = {
        host: options.endpoint.host,
        port: options.endpoint.port,
        path: '/auth/checkToken?authToken=' + options.endpoint.authToken + '&token=' + req.token,
        rejectUnauthorized: false
      };

      getter.get(hoptions,function (response) {
        var body =
          response.on('data', function (chunk) {
            body += chunk;
          });

        response.on('end', function () {
          var responseToken = body.replace('[object Object]', '');
          responseToken = JSON.parse(responseToken);

          if (responseToken.authenticated) {
            req.session.user = responseToken.user;
            return Allowed('login-token', req, res, next);
          }
          else {
            req.user = null;
            if (req.headers['content-type'] === 'application/json;')
              return notAllowed(null, null, req, res);
            else
              return redirectLogin(null, null, req, res);
          }
        });
      }).on('error', function (e) {
          return redirectLogin('[' + req.query.username + ']:[4]:[' + e + ']', 'Username/password not found.', req, res);
        });


    }

    //if trying to login, check against the endpoint that the username/password are valid
    else if (req.url.substring(0, 6) == '/login' && options.endpoint && options.endpoint.host && req.query.username && req.query.password) {
      var getter = (options.endpoint.secure ? require('https') : require('http'));

      var hoptions = {
        host: options.endpoint.host,
        port: options.endpoint.port,
        path: '/auth/login?authToken=' + options.endpoint.authToken + '&username=' + req.query.username + '&password=' + req.query.password,
        rejectUnauthorized: false
      };

      getter.get(hoptions,function (response) {
        var body =
          response.on('data', function (chunk) {
            body += chunk;
          });

        response.on('end', function () {

          var responseToken = body.replace('[object Object]', '');
          responseToken = JSON.parse(responseToken);

          if (!responseToken['joola-token'])
            return redirectLogin('[' + req.query.username + ']:[3b]', 'Username/password not found.', req, res);

          var user = {
            username: responseToken.user.displayName
          };
          req.token = responseToken['joola-token'];
          req.session.token = responseToken['joola-token'];
          req.session.user = user;

          return Allowed('login', req, res, next);
        });
      }).on('error', function (e) {
          return redirectLogin('[' + req.query.username + ']:[4]:[' + e + ']', 'Username/password not found.', req, res);
        });
    }
    else {
      return redirectLogin(null, null, req, res);
    }
  }
};