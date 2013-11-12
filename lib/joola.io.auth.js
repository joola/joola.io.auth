var logger = require('joola.io.logger');

var component_name = global.logger_component || 'auth';

var notAllowed401 = function (err, prettymessage, req, res) {
  if (err) {
    var message = 'Authentication failed [' + req.connection.remoteAddress + ']:' + err;
    logger.warn(message, {component: component_name});
  }
  res.status(401);
  return res.json({result: 'not allowed'});
};

var notAllowed = function (err, prettymessage, req, res) {
  if (err) {
    var message = 'Authentication failed [' + req.connection.remoteAddress + ']:' + err;
    logger.warn(message, {component: component_name});
  }
  return res.render(__dirname + '/../views/login', {reason: prettymessage});
};

var Allowed = function (reason, req, res, next) {
  logger.info('Authentication success [' + reason + ']:[' + req.connection.remoteAddress + ']:[' + req.url + ']:[' + (req.token ? req.token : 'n/a') + ']:[' + req.session.user.username + ']', {component: component_name});

  if (req.url.substring(0, 6) == '/login' && req.query.redirect)
    return res.redirect(req.query.redirect);
  else if (req.url.substring(0, 6) == '/login' && !req.query.redirect)
    return res.redirect('/');
  else
    return next();
};

// the middleware function
module.exports = function (options) {
  return function (req, res, next) {
    if (req.method == 'OPTIONS')
      return next();

    //allow assets without auth
    if (req.url.substring(0, 7) == '/assets' || req.url.substring(0, 5) == '/auth')
      return next();

    if (req.url.substring(0, 7) == '/logout') {
      req.session.destroy(function () {
        res.clearCookie('connect.sid', { path: '/' });
        return notAllowed(null, null, req, res);
      });
      req.user = null;
      return;
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
          //return Allowed('session', req, res, next);
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
        return notAllowed('Not Allowed [2]', 'Username/password not found.', req, res);


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
            req.session.destroy(function () {
              res.clearCookie('connect.sid', { path: '/' });
              return notAllowed(null, null, req, res);
            });
            req.user = null;
            if (req.headers['content-type'] === 'application/json')
              return notAllowed401(null, null, req, res);
            else
              return notAllowed(null, null, req, res);
          }
        });
      }).on('error', function (e) {
          return notAllowed('[' + req.query.username + ']:[4]:[' + e + ']', 'Username/password not found.', req, res);
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
            return notAllowed('[' + req.query.username + ']:[3b]', 'Username/password not found.', req, res);

          var user = {
            username: responseToken.user.displayName
          };
          req.token = responseToken['joola-token'];
          req.session.token = responseToken['joola-token'];
          req.session.user = user;

          return Allowed('login', req, res, next);
        });
      }).on('error', function (e) {
          return notAllowed('[' + req.query.username + ']:[4]:[' + e + ']', 'Username/password not found.', req, res);
        });
    }
    else {
      return notAllowed(null, null, req, res);
    }
  }
};