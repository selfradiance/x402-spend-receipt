import { canonicalJson, canonicalJsonBytes, canonicalSha256Hex, type JsonValue } from "./canonical.js";
import { keyIdFromPublicKey, signBytes, verifyBytes, type Ed25519KeyPair } from "./keys.js";
import { paymentFactsSchema, type PaymentFacts } from "./schemas.js";

const factsSigningPrefix = "xsr/payment_facts/v1\n";

export type UnsignedPaymentFacts = Omit<PaymentFacts, "signature">;

export interface SignedPaymentFactsInput {
  factsId: string;
  timestamp: string;
  receiptId: string;
  receiptHash: string;
  amountBaseUnits: string;
  asset: string;
  network: string;
  payTo: string;
  keyPair: Ed25519KeyPair;
}

export function createSignedPaymentFacts(input: SignedPaymentFactsInput): PaymentFacts {
  const unsignedFacts: UnsignedPaymentFacts = {
    schema_version: "1.0",
    facts_id: input.factsId,
    timestamp: input.timestamp,
    receipt_id: input.receiptId,
    receipt_hash: input.receiptHash,
    amount_base_units: input.amountBaseUnits,
    asset: input.asset,
    network: input.network,
    pay_to: input.payTo,
    key_id: input.keyPair.keyId
  };

  return paymentFactsSchema.parse({
    ...unsignedFacts,
    signature: signBytes(paymentFactsSigningBytes(unsignedFacts), input.keyPair.privateKey)
  });
}

export function verifyPaymentFacts(factsInput: unknown, publicKey: string): boolean {
  const parsed = paymentFactsSchema.safeParse(factsInput);
  if (!parsed.success || parsed.data.key_id !== keyIdFromPublicKey(publicKey)) {
    return false;
  }

  return verifyBytes(paymentFactsSigningBytes(parsed.data), parsed.data.signature, publicKey);
}

export function paymentFactsHash(facts: PaymentFacts): string {
  return canonicalSha256Hex(paymentFactsToJson(facts));
}

export function canonicalPaymentFactsJson(facts: PaymentFacts): string {
  return canonicalJson(paymentFactsToJson(facts));
}

export function paymentFactsSigningBytes(facts: PaymentFacts | UnsignedPaymentFacts): Uint8Array {
  return Buffer.concat([Buffer.from(factsSigningPrefix, "utf8"), canonicalJsonBytes(unsignedPaymentFactsToJson(removeSignature(facts)))]);
}

function removeSignature(facts: PaymentFacts | UnsignedPaymentFacts): UnsignedPaymentFacts {
  return {
    schema_version: facts.schema_version,
    facts_id: facts.facts_id,
    timestamp: facts.timestamp,
    receipt_id: facts.receipt_id,
    receipt_hash: facts.receipt_hash,
    amount_base_units: facts.amount_base_units,
    asset: facts.asset,
    network: facts.network,
    pay_to: facts.pay_to,
    key_id: facts.key_id
  };
}

function unsignedPaymentFactsToJson(facts: UnsignedPaymentFacts): { [key: string]: JsonValue } {
  return {
    schema_version: facts.schema_version,
    facts_id: facts.facts_id,
    timestamp: facts.timestamp,
    receipt_id: facts.receipt_id,
    receipt_hash: facts.receipt_hash,
    amount_base_units: facts.amount_base_units,
    asset: facts.asset,
    network: facts.network,
    pay_to: facts.pay_to,
    key_id: facts.key_id
  };
}

function paymentFactsToJson(facts: PaymentFacts): { [key: string]: JsonValue } {
  return {
    ...unsignedPaymentFactsToJson(facts),
    signature: facts.signature
  };
}
