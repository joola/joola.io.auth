var logger = require('joola.io.logger');

var notAllowed = function (err, req, res) {
  logger.warn('Authentication failed [' + req.connection.remoteAddress + ']: ' + err, {component: 'auth'});
  res.status(401);
  return res.send(err);
};

var Allowed = function (reason, req, res, next) {
  logger.info('Authentication success [' + reason + ']:[' + req.connection.remoteAddress + ']:[' + req.url + ']:[' + (req.token ? req.token : 'n/a') + ']:[' + req.session.user.username + ']', {component: 'auth'});
  return next();
};

// the middleware function
module.exports = function (options) {
  return function (req, res, next) {
    //allow assets without auth
    if (req.url.substring(0, 7) == '/assets')
      return next();

    //anonymous auth is a easy bypass
    if (options.anonymous) {
      var user = {
        username: 'Anonymous'
      };
      req.user = user;
      req.session.user = user;
      return Allowed('anonymous', req, res, next);
    }

    if (req.headers['joola-token'])
      req.query.token = req.headers['joola-token'];

    logger.silly('Request for Authentication [' + req.url + ']:[' + req.connection.remoteAddress + ']:[' + (req.query.token ? req.query.token : 'n/a') + ']', {component: 'auth'});
    //check whitelist for inclusion of ip (if enabled)
    if (options.whitelist && options.whitelist.length > 0)
      if (options.whitelist.indexOf(req.connection.remoteAddress) == -1)
        return notAllowed('Not Allowed [2]', req, res);

    //check we have a valid session for this user
    if (options.sessions) {
      if (req.session) {
        if (req.session.user) {
          return Allowed('session', req, res, next);
        }
      }
    }

    //token checks
    if (req.query.token) {
      req.token = req.query.token;
      //first, bypass token
      if (options.bypassToken) {
        if (options.bypassToken == req.query.token) {
          var user = {
            username: 'Bypass Token'
          };
          req.token = req.query.token;
          req.session.user = user;
          return Allowed('bypass', req, res, next);
        }
      }
      //check the token is valid with the engine
      if (options.endpoint) {
        
      }

    }
    return notAllowed('Not Allowed [1]', req, res);
    //return next();
  }
};