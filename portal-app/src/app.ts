import express from "express";
import path from "node:path";
import cookieParser from "cookie-parser";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import pinoHttp from "pino-http";
import { logger } from "./lib/logger";
import { authRouter } from "./routes/auth.routes";
import { appRouter } from "./routes/app.routes";
import { requireSession } from "./middleware/requireSession";
import { errorHandler } from "./middleware/errorHandler";

export const app = express();

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(helmet());
app.use(
  pinoHttp({
    logger,
    // Only method/URL/status ever get logged — never headers or bodies, so a
    // password, MFA code, or identity assertion can't leak into logs this way.
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

// Blunts distributed brute-force / credential-stuffing across many accounts. The
// per-account lockout itself lives in admin-service, which every login attempt here
// is forwarded to.
const authRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false,
});

app.use("/login", authRateLimiter);

app.use("/", authRouter);
app.use("/", requireSession, appRouter);

app.use((req, res) => {
  res.status(404).send("Not found");
});

app.use(errorHandler);
