import "dotenv/config";
import { z } from "zod";

const schema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().int().positive().default(5000),
  DATABASE_URL: z.string().min(1, "DATABASE_URL is required"),

  // Signs this app's own browser session cookie. Independent of admin-service's
  // session secret by design — each app owns its own session, per the "separate
  // login per app, shared directory only" decision.
  SESSION_SECRET: z.string().min(32, "SESSION_SECRET must be at least 32 characters"),

  // Where admin-service's internal API is reachable, and the credentials to call it.
  ADMIN_SERVICE_URL: z.string().url(),
  ADMIN_SERVICE_INTERNAL_API_KEY: z.string().min(32, "ADMIN_SERVICE_INTERNAL_API_KEY must match admin-service's INTERNAL_API_KEY"),
  // Must match admin-service's INTERNAL_JWT_SECRET exactly — used to verify the
  // identity assertion admin-service hands back after a successful login.
  ADMIN_SERVICE_JWT_SECRET: z.string().min(32, "ADMIN_SERVICE_JWT_SECRET must match admin-service's INTERNAL_JWT_SECRET"),

  APP_BASE_URL: z.string().url(),
});

export const env = schema.parse(process.env);
