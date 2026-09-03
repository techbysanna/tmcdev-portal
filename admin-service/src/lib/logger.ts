import pino from "pino";
import { env } from "../config/env";

// Defense in depth: redact by key name everywhere in the log tree, in addition to
// call sites never passing these fields in the first place. Passwords, MFA secrets/
// codes, tokens, and phone numbers must never reach logs even by accident.
const REDACTED_PATHS = [
  "password",
  "*.password",
  "passwordHash",
  "*.passwordHash",
  "totpSecret",
  "*.totpSecret",
  "totpSecretEncrypted",
  "*.totpSecretEncrypted",
  "code",
  "*.code",
  "mfaCode",
  "*.mfaCode",
  "token",
  "*.token",
  "resetToken",
  "*.resetToken",
  "authorization",
  "*.authorization",
  "req.headers.authorization",
  "req.headers[\"x-internal-api-key\"]",
  "phoneNumber",
  "*.phoneNumber",
];

export const logger = pino({
  level: env.NODE_ENV === "production" ? "info" : "debug",
  redact: {
    paths: REDACTED_PATHS,
    censor: "[REDACTED]",
  },
  formatters: {
    level(label) {
      return { level: label };
    },
  },
});
