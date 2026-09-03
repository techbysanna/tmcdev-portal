import { env } from "../config/env";
import { logger } from "./logger";

export interface EmailMessage {
  to: string;
  subject: string;
  text: string;
}

export interface EmailProvider {
  send(message: EmailMessage): Promise<void>;
}

class ConsoleEmailProvider implements EmailProvider {
  async send(message: EmailMessage): Promise<void> {
    // Dev-only: env.ts refuses to boot with this provider when NODE_ENV=production.
    logger.info({ to: message.to, subject: message.subject }, "[DEV ONLY] email suppressed, logging instead of sending");
    // eslint-disable-next-line no-console
    console.log(`\n[DEV ONLY EMAIL]\nTo: ${message.to}\nSubject: ${message.subject}\n\n${message.text}\n`);
  }
}

class PostmarkEmailProvider implements EmailProvider {
  async send(message: EmailMessage): Promise<void> {
    const res = await fetch("https://api.postmarkapp.com/email", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        "X-Postmark-Server-Token": env.POSTMARK_API_KEY,
      },
      body: JSON.stringify({
        From: env.EMAIL_FROM,
        To: message.to,
        Subject: message.subject,
        TextBody: message.text,
        MessageStream: "outbound",
      }),
    });

    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new Error(`Postmark send failed: ${res.status} ${body}`);
    }
  }
}

export const emailProvider: EmailProvider =
  env.EMAIL_PROVIDER === "postmark" ? new PostmarkEmailProvider() : new ConsoleEmailProvider();
