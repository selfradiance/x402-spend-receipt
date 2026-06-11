import nacl from "tweetnacl";

import { sha256Hex } from "./canonical.js";

export interface Ed25519KeyPair {
  publicKey: string;
  privateKey: string;
  keyId: string;
}

export function generateEd25519KeyPair(): Ed25519KeyPair {
  const keyPair = nacl.sign.keyPair();
  const publicKey = bytesToBase64(keyPair.publicKey);

  return {
    publicKey,
    privateKey: bytesToBase64(keyPair.secretKey),
    keyId: keyIdFromPublicKey(publicKey)
  };
}

export function keyIdFromPublicKey(publicKey: string): string {
  return `ed25519:${sha256Hex(base64ToBytes(publicKey, 32)).slice(0, 16)}`;
}

export function signBytes(message: Uint8Array, privateKey: string): string {
  const privateKeyBytes = base64ToBytes(privateKey, 64);
  return bytesToBase64(nacl.sign.detached(message, privateKeyBytes));
}

export function verifyBytes(message: Uint8Array, signature: string, publicKey: string): boolean {
  try {
    const signatureBytes = base64ToBytes(signature, 64);
    const publicKeyBytes = base64ToBytes(publicKey, 32);
    return nacl.sign.detached.verify(message, signatureBytes, publicKeyBytes);
  } catch {
    return false;
  }
}

function bytesToBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

function base64ToBytes(value: string, expectedLength: number): Uint8Array {
  const bytes = Buffer.from(value, "base64");
  if (bytes.length !== expectedLength) {
    throw new Error(`Expected ${expectedLength} decoded bytes`);
  }

  return new Uint8Array(bytes);
}
