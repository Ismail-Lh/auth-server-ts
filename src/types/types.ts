import type { NextFunction, Request, Response } from 'express';
import type { DeepPartial } from 'utility-types';
import type { IFilterXSSOptions } from 'xss';

// This code defines a type utility called RequireAtLeastOne.
// It takes a generic type T and ensures that at least one property of T is required.
// The resulting type will have all properties of T as required, except for one which will be optional.
// This utility is useful when you want to enforce that at least one property must be present in an object.
// https://stackoverflow.com/questions/61132262/typescript-deep-partial
export type RequireAtLeastOne<T> = {
  [K in keyof T]-?: Required<Pick<T, K>> &
    Partial<Pick<T, Exclude<keyof T, K>>>;
}[keyof T];

// More strictly typed Express.Request type
// https://stackoverflow.com/questions/34508081/how-to-add-typescript-definitions-to-express-req-res
export type TypedRequest<
  ReqBody = Record<string, unknown>,
  QueryString = Record<string, unknown>
> = Request<
  Record<string, unknown>,
  Record<string, unknown>,
  DeepPartial<ReqBody>,
  DeepPartial<QueryString>
>;

// More strictly typed express middleware type
export type ExpressMiddleware<
  ReqBody = Record<string, unknown>,
  Res = Record<string, unknown>,
  QueryString = Record<string, unknown>
> = (
  req: TypedRequest<ReqBody, QueryString>,
  res: Response<Res>,
  next: NextFunction
) => Promise<void> | void;

// Example usage from stackoverflow:
// type Req = { email: string; password: string };

// type Res = { message: string };

// export const signupUser: ExpressMiddleware<Req, Res> = async (req, res) => {
//   /* strongly typed `req.body`. yay autocomplete 🎉 */
//   res.json({ message: 'you have signed up' }) // strongly typed response obj
// };
export interface UserSignUpCredentials {
  username: string;
  email: string;
  password: string;
}

export type UserLoginCredentials = Omit<UserSignUpCredentials, 'username'>;

export interface EmailRequestBody {
  email: string;
}

export interface ResetPasswordRequestBodyType {
  newPassword: string;
}

export type Sanitized<T> = T extends (...args: unknown[]) => unknown
  ? T // if T is a function, return it as is
  : T extends object
  ? {
      readonly [K in keyof T]: Sanitized<T[K]>;
    }
  : T;

export type SanitizeOptions = IFilterXSSOptions & {
  whiteList?: IFilterXSSOptions['whiteList'];
};
