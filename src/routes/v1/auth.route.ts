import { Router } from 'express';
import validateRequest from '../../middleware/validateRequest';
import { loginSchema, signupSchema } from '../../schemas/auth.schema';
import * as authController from '../../controller/auth.controller';

const authRouter = Router();

authRouter.post(
  '/signup',
  validateRequest(signupSchema),
  authController.handleSignUp
);

authRouter.post(
  '/login',
  validateRequest(loginSchema),
  authController.handleLogin
);

authRouter.post('/logout', authController.handleLogout);

authRouter.post('/refresh', authController.handleRefresh);

export default authRouter;
