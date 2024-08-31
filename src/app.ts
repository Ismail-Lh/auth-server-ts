import express, { type Express } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import cookieParser from 'cookie-parser';
import compressFilter from './utils/compressFilter.util';
import { authRouter } from './routes/v1';
import { errorHandler } from './middleware/errorHandler';
import config from './config/config';
import authLimiter from './middleware/authLimiter';
import { xssMiddleware } from './middleware/xssMiddleware';
import path from 'node:path';

// Creates an instance of the Express application.
const app: Express = express();

// Helmet is used to secure this app by configuring the http-header
app.use(helmet());

// Parse json request body
app.use(express.json());

// parse urlencoded request body
app.use(express.urlencoded({ extended: true }));

app.use(xssMiddleware());

app.use(cookieParser());

// Enable compression middleware to compress the response data
app.use(compression({ filter: compressFilter }));

// Enable CORS middleware to allow cross-origin requests
app.use(
  cors({
    // origin is given an array if we want to have multiple origins later
    origin: String(config.cors.cors_origin).split('|'),
    credentials: true
  })
);

if (config.node_env === 'production') {
  app.use('/api/v1/auth', authLimiter);
}

app.use('/api/v1/auth', authRouter);

// app.use('/api/v1', passwordRouter);

// app.use('/api/v1', verifyEmailRouter);

// This code handles all requests that do not match any other route in the application
app.all('*', (req, res) => {
  // Set the response status to 404 (Not Found)
  res.status(404);

  // Check the 'Accept' header of the request to determine the response format
  if (req.accepts('html')) {
    // If the client accepts HTML, send an HTML file as the response
    // The path module is used to construct the file path
    res.sendFile(path.join(__dirname, 'views', '404.html'));
  } else if (req.accepts('json')) {
    // If the client accepts JSON, send a JSON object as the response
    res.json({ error: '404 Not Found' });
  } else {
    // If the client does not accept HTML or JSON, send plain text as the response
    // Set the response content type to 'text/plain'
    res.type('txt').send('404 Not Found');
  }
});

app.use(errorHandler);

export default app;
