import { rateLimit } from 'express-rate-limit';

/**
 * Rate limiter middleware for authentication requests.
 *
 * @remarks
 * This middleware limits the number of requests allowed within a specific time window.
 *
 * @param windowMs - The time window in milliseconds.
 * @param max - The maximum number of requests allowed within the time window.
 * @param skipSuccessfulRequests - Determines whether successful requests should be skipped from rate limiting.
 *
 * @returns The rate limiter middleware.
 */

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  skipSuccessfulRequests: true
});

export default authLimiter;
