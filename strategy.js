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

  validateAccessToken(oAuthProvider, accessToken, options).then(function(oAuthUserId) {
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

function validateAccessToken(oAuthProvider, accessToken, options) {
  switch (oAuthProvider) {
    case 'google':
      return validateGoogleAccessToken(accessToken, options);
    case 'facebook':
      return validateFacebookAccessToken(accessToken, options);
    default:
      return Promise.reject('Unknown OAuth Provider');
  }
}

function validateGoogleAccessToken(accessToken, options) {
  return rp({
    uri: 'https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=' + accessToken,
    method: 'POST'
  }).then(function(res) {
    if (res.data && res.data.audience === options.googleClientId) {
      return res.data.user_id;
    } else {
      return Promise.reject(new Error('Invalid Token'));
    }
  });
}

function validateFacebookAccessToken(accessToken, options) {
  var masterToken = options.facebookClientId + '|' + options.facebookClientSecret;
  var uri = 'https://graph.facebook.com/v2.4/debug_token?input_token=' + accessToken + '&access_token=' + masterToken;

  return rp(uri).then(function(res) {
    if (res.data && res.data.is_valid && res.data.app_id === options.facebookClientId) {
      return res.data.user_id;
    } else {
      return Promise.reject(new Error('Invalid Token'));
    }
  });
}

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;