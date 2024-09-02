import { PrismaClient } from '@prisma/client';
import config from './config';

declare global {
  // eslint-disable-next-line no-var
  var prisma: PrismaClient | undefined;
}

const prismaClient: PrismaClient = new PrismaClient();

if (config.node_env !== 'production') globalThis.prisma = prismaClient;

export default prismaClient;
