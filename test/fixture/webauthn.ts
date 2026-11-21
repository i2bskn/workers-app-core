import { isoCBOR } from "@simplewebauthn/server/helpers";
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from "@simplewebauthn/server";
import { base64UrlDecode, base64UrlEncode } from "../../src/auth/tokens.js";

function join(...pieces: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(pieces.reduce((size, piece) => size + piece.length, 0));
  let offset = 0;
  for (const piece of pieces) {
    bytes.set(piece, offset);
    offset += piece.length;
  }
  return bytes;
}

// A test authenticator with a real Workers Web Crypto key. It signs the RP hash and the client-data hash,
// so the verifier can exercise origin, challenge, counter, user presence and signature checks.
export async function createTestAuthenticator(origin: string, { supportsCounter = true } = {}) {
  const encoder = new TextEncoder();
  const pair = await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  );
  if (!("publicKey" in pair)) throw new Error("expected RSA key pair");
  const publicKey = await crypto.subtle.exportKey("jwk", pair.publicKey);
  if (!("n" in publicKey && "e" in publicKey)) throw new Error("expected RSA public JWK");
  // COSE RSA key: kty=RSA, alg=RS256, modulus, exponent.
  const coseKey = isoCBOR.encode(new Map<number, number | Uint8Array<ArrayBuffer>>([
    [1, 3], [3, -257], [-1, base64UrlDecode(publicKey.n!)!], [-2, base64UrlDecode(publicKey.e!)!],
  ]));
  const rpHash = new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(new URL(origin).hostname)));
  const idBytes = crypto.getRandomValues(new Uint8Array(32));
  const id = base64UrlEncode(idBytes);
  const common = { id, rawId: id, type: "public-key" as const, clientExtensionResults: {} };
  let counter = 0;

  function clientData(type: string, challenge: string) {
    return new Uint8Array(encoder.encode(JSON.stringify({ type, challenge, origin, crossOrigin: false })));
  }

  return {
    async register(challenge: string): Promise<RegistrationResponseJSON> {
      const authData = join(rpHash, new Uint8Array([0x41, 0, 0, 0, 0]), new Uint8Array(16), new Uint8Array([0, idBytes.length]), idBytes, coseKey);
      const attestationObject = isoCBOR.encode(new Map<string, string | Uint8Array<ArrayBuffer> | Map<string, string>>([
        ["fmt", "none"], ["attStmt", new Map<string, string>()], ["authData", authData],
      ]));
      return {
        ...common,
        response: { clientDataJSON: base64UrlEncode(clientData("webauthn.create", challenge)), attestationObject: base64UrlEncode(attestationObject) },
      };
    },
    async authenticate(challenge: string): Promise<AuthenticationResponseJSON> {
      const counterBytes = new Uint8Array(4);
      if (supportsCounter) new DataView(counterBytes.buffer).setUint32(0, ++counter);
      const authenticatorData = join(rpHash, new Uint8Array([0x01]), counterBytes);
      const client = clientData("webauthn.get", challenge);
      const clientHash = new Uint8Array(await crypto.subtle.digest("SHA-256", client));
      const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", pair.privateKey, join(authenticatorData, clientHash));
      return {
        ...common,
        response: {
          clientDataJSON: base64UrlEncode(client),
          authenticatorData: base64UrlEncode(authenticatorData),
          signature: base64UrlEncode(new Uint8Array(signature)),
        },
      };
    },
  };
}
