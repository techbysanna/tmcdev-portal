import { Router } from "express";
import { canViewAuditLog } from "../lib/permissions";

export const appRouter = Router();

appRouter.get("/", (req, res) => {
  const user = req.currentUser!;
  res.render("home", { currentUser: user, canViewAuditLog: canViewAuditLog(user.role) });
});
