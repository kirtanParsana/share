'use strict';
const serverModule = require('../server.js');
const handler = serverModule.default || serverModule;

function apiHandler(req, res) {
  return handler(req, res);
}

module.exports = apiHandler;
module.exports.default = apiHandler;

