import type { NextFunction, Request, Response } from "express";
import { logger } from "../lib/logger";

export function errorHandler(err: unknown, req: Request, res: Response, _next: NextFunction): void {
  logger.error({ err, path: req.path, method: req.method }, "unhandled request error");

  if (res.headersSent) return;

  if (req.get("accept")?.includes("application/json")) {
    res.status(500).json({ error: "internal_error" });
    return;
  }

  res.status(500).send("Something went wrong. Please try again.");
}
