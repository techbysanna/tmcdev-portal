import { env } from "./config/env";
import { app } from "./app";
import { logger } from "./lib/logger";

app.listen(env.PORT, () => {
  logger.info({ port: env.PORT, env: env.NODE_ENV }, "admin-service listening");
});
