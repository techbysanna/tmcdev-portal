import argon2 from "argon2";
import crypto from "node:crypto";
import { env } from "../config/env";

export async function hashPassword(plain: string): Promise<string> {
  return argon2.hash(plain, { type: argon2.argon2id });
}

export async function verifyPassword(hash: string, plain: string): Promise<boolean> {
  try {
    return await argon2.verify(hash, plain);
  } catch {
    return false;
  }
}

export function hashOpaqueToken(token: string): string {
  // Tokens (password reset, SMS codes) are high-entropy or short-lived+rate-limited,
  // so a fast SHA-256 of the raw value is sufficient for at-rest storage; we only
  // ever compare hashes, never store the raw token.
  return crypto.createHash("sha256").update(token).digest("hex");
}

export function generateOpaqueToken(bytes = 32): string {
  return crypto.randomBytes(bytes).toString("base64url");
}

export function generateNumericCode(digits = 6): string {
  const max = 10 ** digits;
  const n = crypto.randomInt(0, max);
  return n.toString().padStart(digits, "0");
}

const MFA_KEY = Buffer.from(env.MFA_ENCRYPTION_KEY, "hex");

export function encryptSecret(plain: string): string {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", MFA_KEY, iv);
  const ciphertext = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([iv, authTag, ciphertext]).toString("base64");
}

export function decryptSecret(encoded: string): string {
  const raw = Buffer.from(encoded, "base64");
  const iv = raw.subarray(0, 12);
  const authTag = raw.subarray(12, 28);
  const ciphertext = raw.subarray(28);
  const decipher = crypto.createDecipheriv("aes-256-gcm", MFA_KEY, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
}

export function timingSafeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}
