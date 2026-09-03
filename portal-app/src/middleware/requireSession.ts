import type { NextFunction, Request, Response } from "express";
import { prisma } from "../db/prisma";
import { signPortalSessionToken, verifyPortalSessionToken } from "../lib/tokens";

const SESSION_COOKIE_NAME = "portal_session";
const isProd = process.env.NODE_ENV === "production";

export const SESSION_COOKIE_OPTIONS = {
  httpOnly: true,
  secure: isProd,
  sameSite: "lax" as const,
  maxAge: 30 * 60 * 1000,
};

export { SESSION_COOKIE_NAME };

declare module "express-serve-static-core" {
  interface Request {
    currentUser?: Awaited<ReturnType<typeof loadUser>>;
  }
}

function loadUser(userId: string) {
  return prisma.portalUser.findUnique({ where: { id: userId } });
}

export async function requireSession(req: Request, res: Response, next: NextFunction): Promise<void> {
  const token = req.cookies?.[SESSION_COOKIE_NAME];
  const claims = token ? verifyPortalSessionToken(token) : null;

  if (!claims) {
    res.redirect("/login");
    return;
  }

  const user = await loadUser(claims.sub);
  if (!user) {
    const { maxAge: _maxAge, ...clearOptions } = SESSION_COOKIE_OPTIONS;
    res.clearCookie(SESSION_COOKIE_NAME, clearOptions);
    res.redirect("/login");
    return;
  }

  req.currentUser = user;

  // Sliding 30-minute inactivity window: every authenticated request refreshes it.
  const refreshed = signPortalSessionToken({ sub: user.id, email: user.email, name: user.name, role: user.role });
  res.cookie(SESSION_COOKIE_NAME, refreshed, SESSION_COOKIE_OPTIONS);

  next();
}
