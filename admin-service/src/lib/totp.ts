import { generateSecret, generateURI, verify } from "otplib";
import QRCode from "qrcode";

export function generateTotpSecret(): string {
  return generateSecret();
}

export async function verifyTotpCode(secret: string, code: string): Promise<boolean> {
  try {
    // epochTolerance of 30s allows the previous/next 30-second step, covering
    // reasonable clock drift between the server and the user's device.
    const result = await verify({ secret, token: code, epochTolerance: 30 });
    return result.valid;
  } catch {
    return false;
  }
}

export async function buildProvisioningQrCodeDataUrl(email: string, secret: string, issuer: string): Promise<string> {
  const otpauthUrl = generateURI({ issuer, label: email, secret });
  return QRCode.toDataURL(otpauthUrl);
}
