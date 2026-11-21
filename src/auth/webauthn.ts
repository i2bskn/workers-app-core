import {
  generateAuthenticationOptions, generateRegistrationOptions, verifyAuthenticationResponse, verifyRegistrationResponse,
  type AuthenticationResponseJSON, type AuthenticatorTransport, type RegistrationResponseJSON,
} from "@simplewebauthn/server";
import { base64UrlDecode, base64UrlEncode } from "./tokens.js";

export type MfaCredential = { id: string; publicKey: string; counter: number; transports?: string[] };

// These optional browser hints are not covered by the authenticator signature.
function transportHints(value: unknown): AuthenticatorTransport[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const supported: AuthenticatorTransport[] = ["ble", "hybrid", "internal", "nfc", "usb"];
  return supported.filter((transport) => value.includes(transport));
}

function descriptor(credential: MfaCredential) {
  return { id: credential.id, transports: transportHints(credential.transports) };
}

export function webauthnRegistrationOptions(
  origin: string,
  brandName: string,
  user: { id: string; email: string },
  credentials: MfaCredential[],
) {
  return generateRegistrationOptions({
    rpName: brandName,
    rpID: new URL(origin).hostname,
    userID: Uint8Array.from(new TextEncoder().encode(user.id)),
    userName: user.email,
    attestationType: "none",
    authenticatorSelection: { residentKey: "preferred", userVerification: "preferred" },
    excludeCredentials: credentials.map(descriptor),
  });
}

export function webauthnAuthenticationOptions(origin: string, credentials: MfaCredential[]) {
  return generateAuthenticationOptions({
    rpID: new URL(origin).hostname,
    allowCredentials: credentials.map(descriptor),
    userVerification: "preferred",
  });
}

export async function verifyWebauthnRegistration(
  origin: string,
  challenge: string,
  response: unknown,
): Promise<MfaCredential | null> {
  try {
    const result = await verifyRegistrationResponse({
      response: response as RegistrationResponseJSON,
      expectedChallenge: challenge,
      expectedOrigin: origin,
      expectedRPID: new URL(origin).hostname,
      // Password was already verified. This permits a user-presence-only hardware key as the second factor.
      requireUserVerification: false,
    });
    if (!result.verified || !result.registrationInfo) return null;
    const credential = result.registrationInfo.credential;
    return {
      id: credential.id,
      publicKey: base64UrlEncode(credential.publicKey),
      counter: credential.counter,
      transports: transportHints(credential.transports),
    };
  } catch {
    return null;
  }
}

export async function verifyWebauthnAuthentication(
  origin: string,
  challenge: string,
  response: unknown,
  credential: MfaCredential,
): Promise<number | null> {
  try {
    const publicKey = base64UrlDecode(credential.publicKey);
    const assertion = response as AuthenticationResponseJSON;
    if (!publicKey || assertion.id !== credential.id) return null;
    const result = await verifyAuthenticationResponse({
      response: assertion,
      expectedChallenge: challenge,
      expectedOrigin: origin,
      expectedRPID: new URL(origin).hostname,
      credential: { id: credential.id, publicKey, counter: credential.counter },
      requireUserVerification: false,
    });
    return result.verified ? result.authenticationInfo.newCounter : null;
  } catch {
    return null;
  }
}
