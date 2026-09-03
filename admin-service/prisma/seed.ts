import "dotenv/config";
import { PrismaClient } from "@prisma/client";
import { APPLICATION_ROLES, APPLICATION_LOGIN_BASE_URLS } from "../src/config/applications";
import { createUserWithSetupLink } from "../src/lib/authService";

const prisma = new PrismaClient();

async function main() {
  for (const key of Object.keys(APPLICATION_ROLES)) {
    const loginBaseUrl = APPLICATION_LOGIN_BASE_URLS[key];
    await prisma.application.upsert({
      where: { key },
      create: { key, name: applicationDisplayName(key), loginBaseUrl },
      update: { loginBaseUrl },
    });
  }
  console.log("Applications seeded:", Object.keys(APPLICATION_ROLES).join(", "));

  const adminEmail = process.env.SEED_ADMIN_EMAIL;
  const adminName = process.env.SEED_ADMIN_NAME ?? "Michael";

  if (!adminEmail) {
    console.log("\nSet SEED_ADMIN_EMAIL (and optionally SEED_ADMIN_NAME) and re-run `npm run seed` to create the first super admin account.");
    return;
  }

  const existing = await prisma.user.findUnique({ where: { email: adminEmail.toLowerCase() } });
  if (existing) {
    console.log(`User ${adminEmail} already exists, skipping.`);
    return;
  }

  const user = await createUserWithSetupLink({
    name: adminName,
    email: adminEmail,
    actorUserId: null,
    actorEmail: "seed-script",
  });
  await prisma.user.update({ where: { id: user.id }, data: { isSuperAdmin: true } });

  console.log(`\nSuper admin account created for ${adminEmail}.`);
  console.log("With EMAIL_PROVIDER=console, the account-setup link was printed above instead of emailed.");
}

function applicationDisplayName(key: string): string {
  return key
    .split("-")
    .map((w) => w[0]!.toUpperCase() + w.slice(1))
    .join(" ");
}

main()
  .catch((err) => {
    console.error(err);
    process.exitCode = 1;
  })
  .finally(() => prisma.$disconnect());
