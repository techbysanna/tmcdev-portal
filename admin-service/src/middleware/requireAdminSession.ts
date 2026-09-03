import type { NextFunction, Request, Response } from "express";
import { prisma } from "../db/prisma";
import { signAdminSessionToken, verifyAdminSessionToken } from "../lib/tokens";
import { canAccessAdminUi } from "../lib/permissions";

const SESSION_COOKIE_NAME = "admin_session";
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

async function loadUser(userId: string) {
  return prisma.user.findUnique({
    where: { id: userId },
    include: { roles: { include: { application: true } } },
  });
}

export async function requireAdminSession(req: Request, res: Response, next: NextFunction): Promise<void> {
  const token = req.cookies?.[SESSION_COOKIE_NAME];
  const claims = token ? verifyAdminSessionToken(token) : null;

  if (!claims) {
    res.redirect("/login");
    return;
  }

  const user = await loadUser(claims.sub);
  if (!user || !user.isActive || !canAccessAdminUi(user)) {
    const { maxAge: _maxAge, ...clearOptions } = SESSION_COOKIE_OPTIONS;
    res.clearCookie(SESSION_COOKIE_NAME, clearOptions);
    res.redirect("/login");
    return;
  }

  req.currentUser = user;

  // Sliding 30-minute inactivity window: every authenticated request refreshes it.
  const refreshed = signAdminSessionToken({ sub: user.id, email: user.email, name: user.name });
  res.cookie(SESSION_COOKIE_NAME, refreshed, SESSION_COOKIE_OPTIONS);

  next();
}
