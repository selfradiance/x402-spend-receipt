import { canonicalJson, canonicalJsonBytes, canonicalSha256Hex, type JsonValue } from "./canonical.js";
import { keyIdFromPublicKey, signBytes, verifyBytes, type Ed25519KeyPair } from "./keys.js";
import { settlementSchema, type Settlement } from "./schemas.js";

const settlementSigningPrefix = "xsr/settlement/v1\n";

export type UnsignedSettlement = Omit<Settlement, "signature">;

export interface SignedSettlementInput {
  settlementId: string;
  timestamp: string;
  receiptId: string;
  receiptHash: string;
  txHash: string;
  network: string;
  keyPair: Ed25519KeyPair;
}

export function createSignedSettlement(input: SignedSettlementInput): Settlement {
  const unsignedSettlement: UnsignedSettlement = {
    schema_version: "1.0",
    settlement_id: input.settlementId,
    timestamp: input.timestamp,
    receipt_id: input.receiptId,
    receipt_hash: input.receiptHash,
    tx_hash: input.txHash,
    network: input.network,
    key_id: input.keyPair.keyId
  };

  return settlementSchema.parse({
    ...unsignedSettlement,
    signature: signBytes(settlementSigningBytes(unsignedSettlement), input.keyPair.privateKey)
  });
}

export function verifySettlement(settlementInput: unknown, publicKey: string): boolean {
  const parsed = settlementSchema.safeParse(settlementInput);
  if (!parsed.success || parsed.data.key_id !== keyIdFromPublicKey(publicKey)) {
    return false;
  }

  return verifyBytes(settlementSigningBytes(parsed.data), parsed.data.signature, publicKey);
}

export function settlementHash(settlement: Settlement): string {
  return canonicalSha256Hex(settlementToJson(settlement));
}

export function canonicalSettlementJson(settlement: Settlement): string {
  return canonicalJson(settlementToJson(settlement));
}

export function settlementSigningBytes(settlement: Settlement | UnsignedSettlement): Uint8Array {
  return Buffer.concat([Buffer.from(settlementSigningPrefix, "utf8"), canonicalJsonBytes(unsignedSettlementToJson(removeSignature(settlement)))]);
}

function removeSignature(settlement: Settlement | UnsignedSettlement): UnsignedSettlement {
  return {
    schema_version: settlement.schema_version,
    settlement_id: settlement.settlement_id,
    timestamp: settlement.timestamp,
    receipt_id: settlement.receipt_id,
    receipt_hash: settlement.receipt_hash,
    tx_hash: settlement.tx_hash,
    network: settlement.network,
    key_id: settlement.key_id
  };
}

function unsignedSettlementToJson(settlement: UnsignedSettlement): { [key: string]: JsonValue } {
  return {
    schema_version: settlement.schema_version,
    settlement_id: settlement.settlement_id,
    timestamp: settlement.timestamp,
    receipt_id: settlement.receipt_id,
    receipt_hash: settlement.receipt_hash,
    tx_hash: settlement.tx_hash,
    network: settlement.network,
    key_id: settlement.key_id
  };
}

function settlementToJson(settlement: Settlement): { [key: string]: JsonValue } {
  return {
    ...unsignedSettlementToJson(settlement),
    signature: settlement.signature
  };
}
