import { canonicalJson, canonicalJsonBytes, canonicalSha256Hex, type JsonValue } from "./canonical.js";
import { keyIdFromPublicKey, signBytes, verifyBytes, type Ed25519KeyPair } from "./keys.js";
import { receiptSchema, type Decision, type ReasonCode, type Receipt } from "./schemas.js";

export type UnsignedReceipt = Omit<Receipt, "signature">;
type JsonObject = { [key: string]: JsonValue };

export interface SignedReceiptInput {
  receiptId: string;
  timestamp: string;
  agentUrn: string;
  intentDigest: string;
  policyDigest: string;
  decision: Decision;
  reasonCode: ReasonCode;
  prevReceiptHash: string | null;
  keyPair: Ed25519KeyPair;
}

export function createSignedReceipt(input: SignedReceiptInput): Receipt {
  const unsignedReceipt: UnsignedReceipt = {
    schema_version: "1.0",
    receipt_id: input.receiptId,
    timestamp: input.timestamp,
    agent_urn: input.agentUrn,
    intent_digest: input.intentDigest,
    policy_digest: input.policyDigest,
    decision: input.decision,
    reason_code: input.reasonCode,
    prev_receipt_hash: input.prevReceiptHash,
    key_id: input.keyPair.keyId
  };

  const receipt = {
    ...unsignedReceipt,
    signature: signBytes(receiptSigningBytes(unsignedReceipt), input.keyPair.privateKey)
  };

  return receiptSchema.parse(receipt);
}

export function verifyReceipt(receiptInput: unknown, publicKey: string): boolean {
  const parsed = receiptSchema.safeParse(receiptInput);
  if (!parsed.success) {
    return false;
  }

  const receipt = parsed.data;
  if (receipt.key_id !== keyIdFromPublicKey(publicKey)) {
    return false;
  }

  return verifyBytes(receiptSigningBytes(receipt), receipt.signature, publicKey);
}

export function receiptHash(receipt: Receipt): string {
  return canonicalSha256Hex(receiptToJson(receipt));
}

export function canonicalReceiptJson(receipt: Receipt): string {
  return canonicalJson(receiptToJson(receipt));
}

export function receiptSigningBytes(receipt: Receipt | UnsignedReceipt): Uint8Array {
  return canonicalJsonBytes(unsignedReceiptToJson(removeSignature(receipt)));
}

function removeSignature(receipt: Receipt | UnsignedReceipt): UnsignedReceipt {
  return {
    schema_version: receipt.schema_version,
    receipt_id: receipt.receipt_id,
    timestamp: receipt.timestamp,
    agent_urn: receipt.agent_urn,
    intent_digest: receipt.intent_digest,
    policy_digest: receipt.policy_digest,
    decision: receipt.decision,
    reason_code: receipt.reason_code,
    prev_receipt_hash: receipt.prev_receipt_hash,
    key_id: receipt.key_id
  };
}

function unsignedReceiptToJson(receipt: UnsignedReceipt): JsonObject {
  return {
    schema_version: receipt.schema_version,
    receipt_id: receipt.receipt_id,
    timestamp: receipt.timestamp,
    agent_urn: receipt.agent_urn,
    intent_digest: receipt.intent_digest,
    policy_digest: receipt.policy_digest,
    decision: receipt.decision,
    reason_code: receipt.reason_code,
    prev_receipt_hash: receipt.prev_receipt_hash,
    key_id: receipt.key_id
  };
}

function receiptToJson(receipt: Receipt): JsonObject {
  return {
    ...unsignedReceiptToJson(receipt),
    signature: receipt.signature
  };
}
