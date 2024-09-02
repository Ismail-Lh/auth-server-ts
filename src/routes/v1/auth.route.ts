import { Router } from 'express';
import validateRequest from '../../middleware/validateRequest';
import { signupSchema, loginSchema } from '../../schemas/auth.schema';
import {
  handleLogin,
  handleLogout,
  // handleRefresh,
  handleSignUp
} from '../../controller/auth.controller';

const authRouter = Router();

authRouter.post('/signup', validateRequest(signupSchema), handleSignUp);

authRouter.post('/login', validateRequest(loginSchema), handleLogin);

authRouter.post('/logout', handleLogout);

// authRouter.post('/refresh', handleRefresh);

export default authRouter;
