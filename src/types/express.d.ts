import { RouteConfig } from '../handler/routeloader.js';

declare global {
  namespace Express {
    interface Request {
      user?: {
        id: string;
        username: string;
      };
      e2eSession?: any;
      routeConfig?: RouteConfig;
      buildHash?: string;
      buildId?: string;
      loaderId?: string;
      userId?: string;
      session?: SessionData;
      pskType?: PskType;
      clientIp: string;
      clientCountry: string;
    }

    interface Response {
      sendModelStream(id: string): void;
      sendStream(bytes: Buffer): void;
    }
  }
}

export {};