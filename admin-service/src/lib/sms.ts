import twilio from "twilio";
import { env } from "../config/env";
import { logger } from "./logger";

const client =
  env.TWILIO_ACCOUNT_SID && env.TWILIO_AUTH_TOKEN
    ? twilio(env.TWILIO_ACCOUNT_SID, env.TWILIO_AUTH_TOKEN)
    : null;

export async function sendSmsCode(toPhoneNumber: string, code: string): Promise<void> {
  if (!client) {
    if (env.NODE_ENV === "production") {
      throw new Error("SMS MFA requested but Twilio is not configured");
    }
    // Dev-only fallback so SMS MFA is testable without real Twilio credentials.
    // Never do this in production: the code below is a login credential.
    logger.warn({ toPhoneNumberMasked: maskPhone(toPhoneNumber) }, "[DEV ONLY] Twilio not configured — printing SMS code to stdout instead of sending it");
    // eslint-disable-next-line no-console
    console.log(`[DEV ONLY] SMS code for ${maskPhone(toPhoneNumber)}: ${code}`);
    return;
  }

  await client.messages.create({
    to: toPhoneNumber,
    from: env.TWILIO_FROM_NUMBER,
    body: `Your verification code is ${code}. It expires in 5 minutes.`,
  });
}

function maskPhone(phone: string): string {
  return phone.replace(/\d(?=\d{2})/g, "*");
}
