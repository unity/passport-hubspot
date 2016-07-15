var OAuth2Strategy = require('passport-oauth2'),
    InternalOAuthError = require('passport-oauth2').InternalOAuthError,
    util = require('util');

/**
 * `Strategy` constructor.
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  options = options || {};
  options.authorizationURL = options.authorizationURL || 'https://app.hubspot.com/auth/authenticate/';
  options.tokenURL = options.tokenURL || 'https://app.hubspot.com/auth/token';
  options.scopeSeparator = options.scopeSeparator || ' ';
  options.skipUserProfile = true

  OAuth2Strategy.call(this, options, verify);
  this.name = 'hubspot';
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);


/**
 * Authenticate request by delegating to a service provider using OAuth 2.0.
 *
 * @param {Object} req
 * @api public
 */
Strategy.prototype.authenticate = function(req, options) {
  options = options || {};

  if (req.query){
    if (req.query.error) {
      // TODO: Error information pertaining to OAuth 2.0 flows is encoded in the
      //       query parameters, and should be propagated to the application.
      return this.fail();
    } else if (req.query.access_token) {
      // Don't redirect again if we're passing the authenticate middleware to the callback endpoint.
      return this.success({
        accessToken: req.query.access_token,
        refreshToken: req.query.refresh_token,
        expiresIn: req.query.expires_in
      });
    }
  }

  OAuth2Strategy.prototype.authenticate.call(this, req, options);
}

/**
 * Append additional parameters to the request.
 * @param  {Object} options
 * @api protected
 */
Strategy.prototype.authorizationParams = function(options) {
  var params = {};

  if (options.portalId) {
    params.portalId = options.portalId;
  }

  return params;
}


module.exports = Strategy;
