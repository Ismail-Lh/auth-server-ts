// eslint-disable-next-line @typescript-eslint/no-require-imports
const jwt = require('jsonwebtoken');

import config from '../config/config';

export const createAccessToken = (userId: number | string): string => {
  return jwt.sign({ userID: userId }, config.jwt.access_token.secret, {
    expiresIn: config.jwt.access_token.expire
  });
};

export const createRefreshToken = (userId: number | string): string => {
  return jwt.sign({ userId }, config.jwt.refresh_token.secret, {
    expiresIn: config.jwt.refresh_token.expire
  });
};
