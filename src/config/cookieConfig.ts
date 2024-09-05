import type { CookieOptions } from 'express';
import config from './config';

export const refreshTokenCookieConfig: CookieOptions = {
  httpOnly: true,
  sameSite: false,
  secure: config.node_env === 'production',
  maxAge: 24 * 60 * 60 * 1000
};

export const clearRefreshTokenCookieConfig: CookieOptions = {
  httpOnly: true,
  sameSite: false,
  secure: config.node_env === 'production'
};
