 import express from 'express';
  import { errors, sendError } from '../../utils/errors.js';
  import logger from '../../handler/logger.js';
  import {
      getUserBuildByHash,
      expireUserBuild,
      deactivateBuild,
      isUserBuildExpired,
      getBuildByHash,
  } from '../../repositories/builds.js';
  import { PSK } from '../../types/psk.js';

  const router = express.Router();

  export const config = {
      auth:       true,
      encrypted:  true,
      allowedPsk: [PSK.LOADER],
  };

  /**
   * Returns the AES key for an existing on-disk build.
   * Requires the build to be activated and within its 14-day window.
   *
   * @route POST /api/v1/build/key
   * @access Loader only
   */
router.post('/api/v1/build/key', async (req: express.Request, res: express.Response) => {
     const userId = req.userId as string;

    try {
      const { build_hash } = req.body;
        if (typeof build_hash !== 'string' || build_hash.length !== 64) {
           logger.warn(`[Build/Key] Invalid build_hash from user '${userId}'`);
           return sendError(res, errors.BAD_REQUEST, `Invalid build_hash from user '${userId}'`);
       }
       const userBuild = await getUserBuildByHash(userId, build_hash);
        if (!userBuild) {
            logger.warn(`[Build/Key] No active user_build for hash '${build_hash}' user '${userId}'`);
            return sendError(res, errors.NOT_FOUND, `No active user_build for hash '${build_hash}' user '${userId}'`);
        }

        if (userBuild?.status != "claimed") {
            logger.warn(`[Build/Key] Build not claimed for user '${userId}' hash '${build_hash}'`);
            return sendError(res, errors.GONE, `Build not claimed for user '${userId}' hash '${build_hash}'`);
        }

        if (await isUserBuildExpired(userBuild)) {
            const build = await getBuildByHash(build_hash);
            if (!build?.is_dev) {
                await expireUserBuild(userBuild.id);
                await deactivateBuild(userBuild.build_id);
                logger.info(`[Build/Key] Build expired for user '${userId}' (activated ${userBuild.activated_at})`);
                return sendError(res, errors.GONE, `Build expired for user '${userId}'`);
           }
        }

        logger.debug(`[Build/Key] Returned AES key for user '${userId}' build '${build_hash}'`);

        return res.json({
             aes_key: userBuild.aes_key,
         });

   } catch (err) {
        logger.error(`[Build/Key] Failed for user '${userId}': ${err}`);
         return sendError(res, errors.INTERNAL, String(err));
  }
});

  export default router;