'use strict';

const typesFactories = [
  require('./me'),
  require('./me-role'),
  require('./register-input'),
  require('./login-input'),
  require('./password-payload'),
  require('./multi-factor-authentication-payload'),
  require('./login-payload'),
  require('./create-role-payload'),
  require('./update-role-payload'),
  require('./delete-role-payload'),
];

/**
 * @param {object} context
 * @param {object} context.nexus
 * @param {object} context.strapi
 * @return {any[]}
 */
module.exports = (context) => typesFactories.map((factory) => factory(context));
