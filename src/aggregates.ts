import { createHash } from "node:crypto";

import { canonicalJson, canonicalJsonBytes, canonicalSha256Hex, type JsonValue } from "./canonical.js";
import { keyIdFromPublicKey, signBytes, verifyBytes, type Ed25519KeyPair } from "./keys.js";
import { aggregateSummarySchema, type AggregateSummary } from "./schemas.js";

const aggregateSigningPrefix = "xsr/aggregate/v1\n";

export type UnsignedAggregateSummary = Omit<AggregateSummary, "signature">;

export interface SignedAggregateSummaryInput extends Omit<UnsignedAggregateSummary, "key_id"> {
  keyPair: Ed25519KeyPair;
}

export function createSignedAggregateSummary(input: SignedAggregateSummaryInput): AggregateSummary {
  const unsignedSummary: UnsignedAggregateSummary = {
    schema_version: input.schema_version,
    aggregate_id: input.aggregate_id,
    created_at: input.created_at,
    range: input.range,
    receipt_count: input.receipt_count,
    decision_counts: input.decision_counts,
    reason_code_counts: input.reason_code_counts,
    invalid_intent_count: input.invalid_intent_count,
    invalid_policy_count: input.invalid_policy_count,
    legacy_unproven_count: input.legacy_unproven_count,
    totals: input.totals,
    first_receipt_hash: input.first_receipt_hash,
    last_receipt_hash: input.last_receipt_hash,
    merkle_root: input.merkle_root,
    key_id: input.keyPair.keyId
  };

  return aggregateSummarySchema.parse({
    ...unsignedSummary,
    signature: signBytes(aggregateSummarySigningBytes(unsignedSummary), input.keyPair.privateKey)
  });
}

export function verifyAggregateSummary(summaryInput: unknown, publicKey: string): boolean {
  const parsed = aggregateSummarySchema.safeParse(summaryInput);
  if (!parsed.success || parsed.data.key_id !== keyIdFromPublicKey(publicKey)) {
    return false;
  }

  return verifyBytes(aggregateSummarySigningBytes(parsed.data), parsed.data.signature, publicKey);
}

export function aggregateSummaryHash(summary: AggregateSummary): string {
  return canonicalSha256Hex(aggregateSummaryToJson(summary));
}

export function canonicalAggregateSummaryJson(summary: AggregateSummary): string {
  return canonicalJson(aggregateSummaryToJson(summary));
}

export function aggregateSummarySigningBytes(summary: AggregateSummary | UnsignedAggregateSummary): Uint8Array {
  return Buffer.concat([
    Buffer.from(aggregateSigningPrefix, "utf8"),
    canonicalJsonBytes(unsignedAggregateSummaryToJson(removeSignature(summary)))
  ]);
}

export function merkleRoot(receiptHashes: readonly string[]): string {
  if (receiptHashes.length === 0) {
    throw new Error("Merkle root requires at least one receipt hash");
  }

  const leaves = receiptHashes.map((hash) => {
    if (!/^[a-f0-9]{64}$/u.test(hash)) {
      throw new TypeError("Receipt hash must be lowercase hexadecimal SHA-256");
    }
    return Buffer.from(hash, "hex");
  });

  return merkleTreeHash(leaves).toString("hex");
}

function merkleTreeHash(leaves: readonly Buffer[]): Buffer {
  if (leaves.length === 1) {
    return sha256(Buffer.concat([Buffer.from([0]), leaves[0] ?? Buffer.alloc(0)]));
  }

  const splitAt = largestPowerOfTwoLessThan(leaves.length);
  const left = merkleTreeHash(leaves.slice(0, splitAt));
  const right = merkleTreeHash(leaves.slice(splitAt));
  return sha256(Buffer.concat([Buffer.from([1]), left, right]));
}

function largestPowerOfTwoLessThan(value: number): number {
  let power = 1;
  while (power * 2 < value) {
    power *= 2;
  }
  return power;
}

function sha256(value: Uint8Array): Buffer {
  return createHash("sha256").update(value).digest();
}

function removeSignature(summary: AggregateSummary | UnsignedAggregateSummary): UnsignedAggregateSummary {
  return {
    schema_version: summary.schema_version,
    aggregate_id: summary.aggregate_id,
    created_at: summary.created_at,
    range: summary.range,
    receipt_count: summary.receipt_count,
    decision_counts: summary.decision_counts,
    reason_code_counts: summary.reason_code_counts,
    invalid_intent_count: summary.invalid_intent_count,
    invalid_policy_count: summary.invalid_policy_count,
    legacy_unproven_count: summary.legacy_unproven_count,
    totals: summary.totals,
    first_receipt_hash: summary.first_receipt_hash,
    last_receipt_hash: summary.last_receipt_hash,
    merkle_root: summary.merkle_root,
    key_id: summary.key_id
  };
}

function unsignedAggregateSummaryToJson(summary: UnsignedAggregateSummary): { [key: string]: JsonValue } {
  return {
    schema_version: summary.schema_version,
    aggregate_id: summary.aggregate_id,
    created_at: summary.created_at,
    range: summary.range,
    receipt_count: summary.receipt_count,
    decision_counts: summary.decision_counts,
    reason_code_counts: summary.reason_code_counts,
    invalid_intent_count: summary.invalid_intent_count,
    invalid_policy_count: summary.invalid_policy_count,
    legacy_unproven_count: summary.legacy_unproven_count,
    totals: summary.totals,
    first_receipt_hash: summary.first_receipt_hash,
    last_receipt_hash: summary.last_receipt_hash,
    merkle_root: summary.merkle_root,
    key_id: summary.key_id
  };
}

function aggregateSummaryToJson(summary: AggregateSummary): { [key: string]: JsonValue } {
  return {
    ...unsignedAggregateSummaryToJson(summary),
    signature: summary.signature
  };
}
