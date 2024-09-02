import type { Response } from 'express';
import httpStatus from 'http-status';
// import { randomUUID } from 'node:crypto';
import bcrypt from 'bcryptjs';
// import jwt, { JwtPayload } from 'jsonwebtoken';

// const { verify } = jwt;

import prismaClient from '../config/prisma';
import type {
  TypedRequest,
  UserLoginCredentials,
  UserSignUpCredentials
} from '../types/types';

import config from '../config/config';

import {
  createAndSaveNewTokens,
  handleExistingRefreshToken,
  userExists
} from '../helpers/auth.helper';
import { clearRefreshTokenCookieConfig } from '../config/cookieConfig';

// import { sendVerifyEmail } from '../utils/sendEmail.util';
// import logger from '../middleware/logger';

/**
 * This function handles the signup process for new users. It expects a request object with the following properties:
 *
 * @param {TypedRequest<UserSignUpCredentials>} req - The request object that includes user's username, email, and password.
 * @param {Response} res - The response object that will be used to send the HTTP response.
 *
 * @returns {Response} Returns an HTTP response that includes one of the following:
 *   - A 400 BAD REQUEST status code and an error message if the request body is missing any required parameters.
 *   - A 409 CONFLICT status code if the user email already exists in the database.
 *   - A 201 CREATED status code and a success message if the new user is successfully created and a verification email is sent.
 *   - A 500 INTERNAL SERVER ERROR status code if there is an error in the server.
 */
export const handleSignUp = async (
  req: TypedRequest<UserSignUpCredentials>,
  res: Response
) => {
  const { username, email, password } = req.body;

  // check req.body values
  if (!username || !email || !password) {
    return res.status(httpStatus.BAD_REQUEST).json({
      message: 'Username, email and password are required!'
    });
  }

  const checkUserEmail = await userExists(email);

  if (checkUserEmail) {
    return res.status(httpStatus.CONFLICT).json({
      message: 'Email is already in use! Please use another email!'
    });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 12);

    const newUser = await prismaClient.user.create({
      data: {
        name: username,
        email,
        password: hashedPassword
      }
    });

    // const token = randomUUID();
    // const expiresAt = new Date(Date.now() + 3600000); // Token expires in 1 hour

    // await prismaClient.emailVerificationToken.create({
    //   data: {
    //     token,
    //     expiresAt,
    //     userId: newUser.id
    //   }
    // });

    // // Send an email with the verification link
    // sendVerifyEmail(email, token);

    res.status(httpStatus.CREATED).json({
      message: 'New user created successfully!',
      user: { name: newUser.name, email: newUser.email }
    });
  } catch (err) {
    res.status(httpStatus.INTERNAL_SERVER_ERROR).json({ error: err });
  }
};

/**
 * This function handles the login process for users. It expects a request object with the following properties:
 *
 * @param {TypedRequest<UserLoginCredentials>} req - The request object that includes user's email and password.
 * @param {Response} res - The response object that will be used to send the HTTP response.
 *
 * @returns {Response} Returns an HTTP response that includes one of the following:
 *   - A 400 BAD REQUEST status code and an error message if the request body is missing any required parameters.
 *   - A 401 UNAUTHORIZED status code if the user email does not exist in the database or the email is not verified or the password is incorrect.
 *   - A 200 OK status code and an access token if the login is successful and a new refresh token is stored in the database and a new refresh token cookie is set.
 *   - A 500 INTERNAL SERVER ERROR status code if there is an error in the server.
 */

export const handleLogin = async (
  req: TypedRequest<UserLoginCredentials>,
  res: Response
): Promise<Response> => {
  const cookies = req.cookies;

  const { email, password } = req.body;

  if (!email || !password) {
    return res
      .status(httpStatus.BAD_REQUEST)
      .json({ message: 'Email and password are required!' });
  }

  const user = await userExists(email);

  if (!user)
    return res
      .status(httpStatus.UNAUTHORIZED)
      .json({ message: 'Unauthorized access. Please check your credentials.' });

  // check if email is verified
  // if (!user.emailVerified) {
  //   res.status(httpStatus.UNAUTHORIZED).json({
  //     message: 'Your email is not verified! Please confirm your email!'
  //   });
  // }

  try {
    // check password
    const isPasswordCorrect = await bcrypt.compare(password, user.password);

    // if the password is correct, then we create a new access token and a new refresh token
    if (isPasswordCorrect) {
      // get the refresh token from the cookie
      const refreshTokenName = config.jwt.refresh_token.cookie_name;
      const RefreshTokenFromCookies = cookies[refreshTokenName];

      //  check if the refresh token exists in the cookie
      if (RefreshTokenFromCookies) {
        await handleExistingRefreshToken(RefreshTokenFromCookies, user.id, res);
      }

      // Create new access token
      const accessToken = await createAndSaveNewTokens(user.id, res);

      // Send the access token to the client (frontend)
      return res.json({ accessToken });
    }

    // If the password is incorrect then we return an unauthorized status
    return res
      .status(httpStatus.UNAUTHORIZED)
      .json({ message: 'Unauthorized access. Please check your credentials.' });
  } catch (err) {
    return res.status(httpStatus.INTERNAL_SERVER_ERROR).json({ error: err });
  }
};

/**
 * This function handles the logout process for users. It expects a request object with the following properties:
 *
 * @param {TypedRequest} req - The request object that includes a cookie with a valid refresh token
 * @param {Response} res - The response object that will be used to send the HTTP response.
 *
 * @returns {Response} Returns an HTTP response that includes one of the following:
 *   - A 204 NO CONTENT status code if the refresh token cookie is undefined
 *   - A 204 NO CONTENT status code if the refresh token does not exists in the database
 *   - A 204 NO CONTENT status code if the refresh token cookie is successfully cleared
 */
export const handleLogout = async (
  req: TypedRequest,
  res: Response
): Promise<Response> => {
  const cookies = req.cookies;

  const refreshTokenFromCookies = cookies[config.jwt.refresh_token.cookie_name];

  if (!refreshTokenFromCookies) {
    return res.sendStatus(httpStatus.NO_CONTENT);
  }

  // Is refreshToken in db?
  const refreshTokenFromDB = await prismaClient.refreshToken.findUnique({
    where: { token: refreshTokenFromCookies }
  });

  if (!refreshTokenFromDB) {
    res.clearCookie(
      config.jwt.refresh_token.cookie_name,
      clearRefreshTokenCookieConfig
    );
    return res.sendStatus(httpStatus.NO_CONTENT);
  }

  // Delete refreshToken in db
  await prismaClient.refreshToken.delete({
    where: { token: refreshTokenFromCookies }
  });

  res.clearCookie(
    config.jwt.refresh_token.cookie_name,
    clearRefreshTokenCookieConfig
  );

  return res.sendStatus(httpStatus.NO_CONTENT);
};

/**
 * This function handles the refresh process for users. It expects a request object with the following properties:
 *
 * @param {Request} req - The request object that includes a cookie with a valid refresh token
 * @param {Response} res - The response object that will be used to send the HTTP response.
 *
 * @returns {Response} Returns an HTTP response that includes one of the following:
 *   - A 401 UNAUTHORIZED status code if the refresh token cookie is undefined
 *   - A 403 FORBIDDEN status code if a refresh token reuse was detected but the token wasn't valid
 *   - A 403 FORBIDDEN status code if a refresh token reuse was detected but the token was valid
 *   - A 403 FORBIDDEN status code if the token wasn't valid
 *   - A 200 OK status code if the token was valid and the user was granted a new refresh and access token
 */
// export const handleRefresh = async (req: Request, res: Response) => {
//   const refreshToken: string | undefined =
//     req.cookies[config.jwt.refresh_token.cookie_name];

//   if (!refreshToken) return res.sendStatus(httpStatus.UNAUTHORIZED);

//   // clear refresh cookie
//   res.clearCookie(
//     config.jwt.refresh_token.cookie_name,
//     clearRefreshTokenCookieConfig
//   );

//   // check if refresh token is in db
//   const foundRefreshToken = await prismaClient.refreshToken.findUnique({
//     where: {
//       token: refreshToken
//     }
//   });

//   // Detected refresh token reuse!
//   if (!foundRefreshToken) {
//     verify(
//       refreshToken,
//       config.jwt.refresh_token.secret,
//       async (err: unknown, payload: JwtPayload) => {
//         if (err) return res.sendStatus(httpStatus.FORBIDDEN);

//         logger.warn('Attempted refresh token reuse!');

//         // Delete all tokens of the user because we detected that a token was stolen from him
//         await prismaClient.refreshToken.deleteMany({
//           where: {
//             userId: payload.userId
//           }
//         });
//       }
//     );
//     return res.status(httpStatus.FORBIDDEN);
//   }

//   // delete from db
//   await prismaClient.refreshToken.delete({
//     where: {
//       token: refreshToken
//     }
//   });

//   // evaluate jwt
//   verify(
//     refreshToken,
//     config.jwt.refresh_token.secret,
//     async (err: unknown, payload: JwtPayload) => {
//       if (err || foundRefreshToken.userId !== payload.userId) {
//         return res.sendStatus(httpStatus.FORBIDDEN);
//       }

//       // Refresh token was still valid
//       const accessToken = createAccessToken(payload.userId);

//       const newRefreshToken = createRefreshToken(payload.userId);

//       // add refresh token to db
//       await prismaClient.refreshToken
//         .create({
//           data: {
//             token: newRefreshToken,
//             userId: payload.userId
//           }
//         })
//         .catch((err: Error) => {
//           logger.error(err);
//         });

//       // Creates Secure Cookie with refresh token
//       res.cookie(
//         config.jwt.refresh_token.cookie_name,
//         newRefreshToken,
//         refreshTokenCookieConfig
//       );

//       return res.json({ accessToken });
//     }
//   );
// };
