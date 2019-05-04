'use strict';

const extend = require('extend');
const jwt = require('jsonwebtoken');

const modelError = require('./error');

const RIGHT_SEPARATOR = '.';
const RIGHT_WILDCARD = '*';

function factory(_router, _config) {
  const config = Object.assign({
    keys: {}
  }, _config);

  function sign(_payload, _alias, _options) {
    const key = config.keys[_alias];
    if (!key) {
      throw new modelError(`Unknown [${_alias}] key`);
    } else if (!key.privateKey) {
      throw new modelError(`Missing private key for [${_alias}] key`);
    }

    const options = extend(true, {}, _options, {
      kid: key.kid,
      algorithm: key.algorithm
    });

    return jwt.sign(_payload, key.privateKey, options);
  }

  function hasRight(_token, _right) {
    const parts = _right.toString().split(RIGHT_SEPARATOR);
    let pointer = _token.rights;
    for (const part of parts) {
      if (pointer === RIGHT_WILDCARD) {
        return true;
      } else if (!(part in pointer)) {
        return false;
      }

      pointer = pointer[part];
    }

    return true;
  }

  function checkRight(_token, _right) {
    if (!hasRight(_token, _right)) {
      throw new modelError(`Token doesn't hold the requested [${_right}] right`);
    }
  }

  function verify(_token, _alias, _options) {
    const key = config.keys[_alias];
    if (!key) {
      throw new modelError(`Unknown [${_alias}] key`);
    }

    const options = extend(true, {}, _options, {
      kid: key.kid,
      algorithm: key.algorithm
    });

    const token = jwt.verify(_token, key.publicKey, options);

    Object.defineProperties(token, {
      hasRight: {value: _right => hasRight(token, _right)},
      checkRight: {value: _right => checkRight(token, _right)}
    });

    return token;
  }

  _router.decorate('jwt', {
    sign,
    verify,
    checkRight
  });

  _router.decorateStream('jwt', function(_alias, _options) {
    const header = this.in.authorization;
    if (!header) {
      throw new modelError('Missing authorization header');
    } else if (header.substring(0, 6) !== 'Bearer') {
      throw new modelError('Invalid header format');
    }

    const raw = header.substring(6).trim();
    return verify(raw, _alias, _options);
  });
}

Object.defineProperties(factory, {
  JWTError: {enumerable: true, value: modelError}
});

module.exports = factory;
