import "dotenv/config";
import { z } from "zod";

const baseSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().int().positive().default(4000),
  DATABASE_URL: z.string().min(1, "DATABASE_URL is required"),
  SESSION_SECRET: z.string().min(32, "SESSION_SECRET must be at least 32 characters"),
  INTERNAL_JWT_SECRET: z.string().min(32, "INTERNAL_JWT_SECRET must be at least 32 characters"),
  INTERNAL_API_KEY: z.string().min(32, "INTERNAL_API_KEY must be at least 32 characters"),
  MFA_ENCRYPTION_KEY: z
    .string()
    .regex(/^[0-9a-f]{64}$/i, "MFA_ENCRYPTION_KEY must be 64 hex characters (32 bytes)"),
  TWILIO_ACCOUNT_SID: z.string().optional().default(""),
  TWILIO_AUTH_TOKEN: z.string().optional().default(""),
  TWILIO_FROM_NUMBER: z.string().optional().default(""),
  EMAIL_PROVIDER: z.enum(["console", "postmark"]).default("console"),
  EMAIL_FROM: z.string().min(1).default("no-reply@example.com"),
  POSTMARK_API_KEY: z.string().optional().default(""),
  APP_BASE_URL: z.string().url(),
});

const parsed = baseSchema.parse(process.env);

if (parsed.NODE_ENV === "production" && parsed.EMAIL_PROVIDER === "console") {
  throw new Error(
    "EMAIL_PROVIDER=console is a dev-only stub that logs reset links instead of emailing them. " +
      "Set EMAIL_PROVIDER=postmark and POSTMARK_API_KEY before running in production.",
  );
}

if (parsed.NODE_ENV === "production" && (!parsed.TWILIO_ACCOUNT_SID || !parsed.TWILIO_AUTH_TOKEN || !parsed.TWILIO_FROM_NUMBER)) {
  throw new Error("TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, and TWILIO_FROM_NUMBER are required in production (SMS MFA is enabled).");
}

export const env = parsed;
