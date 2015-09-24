/**
 * Module dependencies.
 */
var passport = require('passport-strategy');
var rp = require('request-promise');
var Promise = require('bluebird');
var util = require('util');
var lookup = require('./utils').lookup;


function Strategy(options, verify) {
  if (typeof options === 'function') {
    verify = options;
    options = {};
  }
  if (!verify) {
    throw new TypeError('OAuthAccessTokenStrategy requires a verify callback');
  }

  this._oAuthProviderField = options.oAuthProviderField || 'oAuthProvider';
  this._accessTokenField = options.accessTokenField || 'accessToken';

  this._googleClientId = options.googleClientId;
  this._facebookClientId = options.facebookClientId;
  this._facebookClientSecret = options.facebookClientSecret;

  passport.Strategy.call(this);
  this.name = 'oAuthAccessToken';
  this._verify = verify;
  this._passReqToCallback = options.passReqToCallback;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request based on the contents of a form submission.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {
  options = options || {};
  var oAuthProvider = lookup(req.body, this._oAuthProviderField) || lookup(req.query, this._oAuthProviderField);
  var accessToken = lookup(req.body, this._accessTokenField) || lookup(req.query, this._accessTokenField);

  if (!oAuthProvider) {
    return this.fail({
      message: options.badRequestMessage || 'Missing OAuth Provider Name'
    }, 400);
  }

  if (!accessToken) {
    return this.fail({
      message: options.badRequestMessage || 'Missing Access Token'
    }, 400);
  }

  var self = this;

  validateAccessToken.call(self, oAuthProvider, accessToken).then(function(oAuthUserId) {
    function verified(err, user, info) {
      if (err) {
        return self.error(err);
      }
      if (!user) {
        return self.fail(info);
      }
      self.success(user, info);
    }

    try {
      if (self._passReqToCallback) {
        this._verify(req, accessToken, oAuthUserId, verified);
      } else {
        this._verify(accessToken, oAuthUserId, verified);
      }
    } catch (ex) {
      return self.error(ex);
    }
  }).catch(function(err) {
    return self.error(err);
  });
};

function validateAccessToken(oAuthProvider, accessToken) {
  switch (oAuthProvider) {
    case 'google':
      return validateGoogleAccessToken.call(this, accessToken);
    case 'facebook':
      return validateFacebookAccessToken.call(this, accessToken);
    default:
      return Promise.reject('Unknown OAuth Provider: ' + oAuthProvider);
  }
}

function validateGoogleAccessToken(accessToken) {
  var self = this;

  if (!self._googleClientId) {
    return Promise.reject(new Error('Missing Google Client ID'));
  }

  return jsonRequest({
    uri: 'https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=' + accessToken,
    method: 'POST'
  }).then(function(data) {
    if (data && data.audience === self._googleClientId) {
      return data.user_id;
    } else {
      return Promise.reject(new Error('Invalid Token'));
    }
  });
}

function validateFacebookAccessToken(accessToken) {
  var self = this;

  if (!self._facebookClientId) {
    return Promise.reject(new Error('Missing Facebook Client ID'));
  }

  if (!self._facebookClientSecret) {
    return Promise.reject(new Error('Missing Facebook Client Secret'));
  }

  var masterToken = self._facebookClientId + '|' + self._facebookClientSecret;
  var uri = 'https://graph.facebook.com/v2.4/debug_token?input_token=' + accessToken + '&access_token=' + masterToken;

  return jsonRequest(uri).then(function(data) {
    if (data && data.is_valid && data.app_id === self._facebookClientId) {
      return data.user_id;
    } else {
      return Promise.reject(new Error('Invalid Token'));
    }
  });
}

function jsonRequest(reqData) {
  return rp(reqData).then(parseBody);
}

function parseBody(body) {
  try {
    return Promise.resolve(JSON.parse(body));
  } catch (e) {
    return Promise.reject(
      new Error(util.format('Parsing error: %s, body= \n %s', e.message, body))
    );
  }
}

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;