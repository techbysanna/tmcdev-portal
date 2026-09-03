import express from "express";
import path from "node:path";
import cookieParser from "cookie-parser";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import pinoHttp from "pino-http";
import { logger } from "./lib/logger";
import { authRouter } from "./routes/auth.routes";
import { adminRouter } from "./routes/admin.routes";
import { internalRouter } from "./routes/internal.routes";
import { requireAdminSession } from "./middleware/requireAdminSession";
import { requireInternalApiKey } from "./middleware/requireInternalApiKey";
import { errorHandler } from "./middleware/errorHandler";

export const app = express();

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(helmet());
app.use(
  pinoHttp({
    logger,
    // Full request/response objects would otherwise flow through pino's default
    // serializers, which is how headers (auth tokens, cookies) and bodies leak into
    // logs. Log only the minimal, non-sensitive shape we actually need.
    serializers: {
      req(req) {
        return { method: req.method, url: req.url };
      },
      res(res) {
        return { statusCode: res.statusCode };
      },
    },
  }),
);
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "..", "public")));

// Blunts distributed brute-force / credential-stuffing across many accounts, on top
// of the per-account lockout in lib/lockout.ts (which handles targeted attacks on one
// account regardless of source IP).
const authRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(["/login", "/internal/auth"], authRateLimiter);

app.use("/", authRouter);
app.use("/internal", requireInternalApiKey, internalRouter);
app.use("/", requireAdminSession, adminRouter);

app.use((req, res) => {
  res.status(404).send("Not found");
});

app.use(errorHandler);
