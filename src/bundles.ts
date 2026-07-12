import { canonicalJson, canonicalJsonBytes, canonicalSha256Hex, type JsonValue } from "./canonical.js";
import { keyIdFromPublicKey, signBytes, verifyBytes, type Ed25519KeyPair } from "./keys.js";
import { auditBundleManifestSchema, type AuditBundleManifest } from "./schemas.js";

const bundleSigningPrefix = "xsr/bundle/v1\n";

export type UnsignedAuditBundleManifest = Omit<AuditBundleManifest, "signature">;

export interface SignedAuditBundleManifestInput extends Omit<UnsignedAuditBundleManifest, "key_id"> {
  keyPair: Ed25519KeyPair;
}

export function createSignedAuditBundleManifest(input: SignedAuditBundleManifestInput): AuditBundleManifest {
  const unsignedManifest: UnsignedAuditBundleManifest = {
    schema_version: input.schema_version,
    bundle_id: input.bundle_id,
    created_at: input.created_at,
    receipts: input.receipts,
    files: input.files,
    summary_sha256: input.summary_sha256,
    key_id: input.keyPair.keyId
  };

  return auditBundleManifestSchema.parse({
    ...unsignedManifest,
    signature: signBytes(auditBundleManifestSigningBytes(unsignedManifest), input.keyPair.privateKey)
  });
}

export function verifyAuditBundleManifest(manifestInput: unknown, publicKey: string): boolean {
  const parsed = auditBundleManifestSchema.safeParse(manifestInput);
  if (!parsed.success || parsed.data.key_id !== keyIdFromPublicKey(publicKey)) {
    return false;
  }

  return verifyBytes(auditBundleManifestSigningBytes(parsed.data), parsed.data.signature, publicKey);
}

export function auditBundleManifestHash(manifest: AuditBundleManifest): string {
  return canonicalSha256Hex(auditBundleManifestToJson(manifest));
}

export function canonicalAuditBundleManifestJson(manifest: AuditBundleManifest): string {
  return canonicalJson(auditBundleManifestToJson(manifest));
}

export function auditBundleManifestSigningBytes(manifest: AuditBundleManifest | UnsignedAuditBundleManifest): Uint8Array {
  return Buffer.concat([
    Buffer.from(bundleSigningPrefix, "utf8"),
    canonicalJsonBytes(unsignedAuditBundleManifestToJson(removeSignature(manifest)))
  ]);
}

function removeSignature(manifest: AuditBundleManifest | UnsignedAuditBundleManifest): UnsignedAuditBundleManifest {
  return {
    schema_version: manifest.schema_version,
    bundle_id: manifest.bundle_id,
    created_at: manifest.created_at,
    receipts: manifest.receipts,
    files: manifest.files,
    summary_sha256: manifest.summary_sha256,
    key_id: manifest.key_id
  };
}

function unsignedAuditBundleManifestToJson(manifest: UnsignedAuditBundleManifest): { [key: string]: JsonValue } {
  return {
    schema_version: manifest.schema_version,
    bundle_id: manifest.bundle_id,
    created_at: manifest.created_at,
    receipts: manifest.receipts,
    files: manifest.files,
    summary_sha256: manifest.summary_sha256,
    key_id: manifest.key_id
  };
}

function auditBundleManifestToJson(manifest: AuditBundleManifest): { [key: string]: JsonValue } {
  return {
    ...unsignedAuditBundleManifestToJson(manifest),
    signature: manifest.signature
  };
}
