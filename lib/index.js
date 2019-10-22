'use strict';

const {JWTError} = require('titan-jwt');

function factory(_router, _jwt) {
  _router.decorate('jwt', {
    sign: _jwt.sign,
    verify: _jwt.verify,
    hasRight: _jwt.hasRight,
    checkRight: _jwt.checkRight
  });

  _router.decorateStream('jwt', function(_scope, _options) {
    const header = this.in.authorization;
    if (!header) {
      throw new JWTError('Missing authorization header');
    } else if (header.substring(0, 6) !== 'Bearer') {
      throw new JWTError('Invalid header format');
    }

    const raw = header.substring(6).trim();
    return _jwt.verify(raw, _scope, _options);
  });
}

Object.defineProperties(factory, {
  JWTError: {enumerable: true, value: JWTError}
});

module.exports = factory;
