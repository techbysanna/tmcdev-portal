import pino from "pino";
import { env } from "../config/env";

// Defense in depth against the "no document contents/tax details/sensitive data in
// logs" requirement: redact by key name everywhere in the log tree, in addition to
// call sites never passing these fields in the first place.
const REDACTED_PATHS = [
  "password",
  "*.password",
  "code",
  "*.code",
  "token",
  "*.token",
  "identityAssertion",
  "*.identityAssertion",
  "authorization",
  "*.authorization",
  "req.headers.authorization",
  "req.headers[\"x-internal-api-key\"]",
  "phoneNumber",
  "*.phoneNumber",
  // Document content itself never flows through the app process (files are streamed
  // from Dropbox straight to the response, see lib/dropbox.ts once step 3/4 land),
  // but keep these in place as a backstop against ever logging a document buffer.
  "fileContents",
  "*.fileContents",
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
