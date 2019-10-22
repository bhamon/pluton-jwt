'use strict';

const {JWTError} = require('titan-jwt');

function factory(_router, _config) {
  _router.decorate('jwt', {
    sign: _config.jwt.sign,
    verify: _config.jwt.verify,
    hasRight: _config.jwt.hasRight,
    checkRight: _config.jwt.checkRight
  });

  _router.decorateStream('jwt', function(_scope, _options) {
    const header = this.in.authorization;
    if (!header) {
      throw new JWTError('Missing authorization header');
    } else if (header.substring(0, 6) !== 'Bearer') {
      throw new JWTError('Invalid header format');
    }

    const raw = header.substring(6).trim();
    return _config.jwt.verify(raw, _scope, _options);
  });
}

Object.defineProperties(factory, {
  JWTError: {enumerable: true, value: JWTError}
});

module.exports = factory;
