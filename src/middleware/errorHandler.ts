import type { Request, Response } from 'express';
import logger from './logger';

/**
 * Handles errors and sends an error response with a status code of 500.
 *
 * @param err - The error object to be handled.
 * @param _req - The request object (not used in this function).
 * @param res - The response object to send the error response.
 */
export const errorHandler = (
  err: Error,
  _req: Request,
  res: Response
): void => {
  logger.error(err);

  res.status(500).json({ message: err.message });
};
