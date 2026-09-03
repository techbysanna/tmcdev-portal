import type { NextFunction, Request, Response } from "express";
import { env } from "../config/env";
import { timingSafeEqual } from "../lib/crypto";

// Guards /internal/* routes, which are meant to be called server-to-server by other
// apps (e.g. portal-app), never directly by a browser.
export function requireInternalApiKey(req: Request, res: Response, next: NextFunction): void {
  const provided = req.get("x-internal-api-key");
  if (!provided || !timingSafeEqual(provided, env.INTERNAL_API_KEY)) {
    res.status(401).json({ error: "unauthorized" });
    return;
  }
  next();
}
