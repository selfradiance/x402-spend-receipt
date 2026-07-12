import { randomUUID } from "node:crypto";

import { canonicalJson } from "./canonical.js";
import { createSignedAggregateSummary, merkleRoot, verifyAggregateSummary } from "./aggregates.js";
import { verifyChain } from "./chain.js";
import {
  type ReceiptLedgerReader,
  type StoredPaymentFactsRow,
  type StoredReceiptRow,
  type StoredSettlementRow
} from "./ledger.js";
import { mapFactsNetwork } from "./network.js";
import { receiptHash, verifyReceipt } from "./receipts.js";
import { verifyPaymentFacts } from "./facts.js";
import { verifySettlement } from "./settlements.js";
import {
  aggregateSummarySchema,
  isFactsEligibleReasonCode,
  paymentFactsSchema,
  receiptSchema,
  reasonCodes,
  settlementSchema,
  type AggregateRange,
  type AggregateSummary,
  type AggregateTotals,
  type Decision,
  type PaymentFacts,
  type ReasonCode,
  type Receipt,
  type Settlement
} from "./schemas.js";
import { type Ed25519KeyPair } from "./keys.js";

export type AggregationErrorCode =
  | "CHAIN_INVALID"
  | "EMPTY_RANGE"
  | "INVALID_RANGE"
  | "LEGACY_RECEIPTS_IN_RANGE"
  | "RECEIPT_NOT_FOUND"
  | "RECEIPT_SIGNATURE_INVALID"
  | "FACTS_CARDINALITY_INVALID"
  | "FACTS_SIGNATURE_INVALID"
  | "SETTLEMENT_CARDINALITY_INVALID"
  | "SETTLEMENT_SIGNATURE_INVALID"
  | "SETTLEMENT_BINDING_INVALID"
  | "SETTLEMENT_NETWORK_MISMATCH"
  | "SUMMARY_SIGNATURE_INVALID"
  | "TOTALS_MISMATCH";

export class AggregationError extends Error {
  constructor(
    readonly code: AggregationErrorCode,
    message: string
  ) {
    super(message);
  }
}

export interface AggregateLedgerOptions {
  range: AggregateRange;
  allowLegacy?: boolean;
  aggregateId?: string;
  createdAt?: Date;
  keyPair: Ed25519KeyPair;
}

export interface AggregationArtifacts {
  summary: AggregateSummary;
  receiptRows: readonly StoredReceiptRow[];
  paymentFactsRows: readonly StoredPaymentFactsRow[];
  settlementRows: readonly StoredSettlementRow[];
}

export interface AggregateVerificationResult {
  valid: boolean;
  code?: AggregationErrorCode;
  error?: string;
}

interface SelectedReceipt {
  row: StoredReceiptRow;
  receipt: Receipt;
}

interface ComputedAggregate {
  range: AggregateRange;
  receiptCount: number;
  decisionCounts: Record<Decision, number>;
  reasonCodeCounts: Record<ReasonCode, number>;
  invalidIntentCount: number;
  invalidPolicyCount: number;
  legacyUnprovenCount: number;
  totals: AggregateTotals[];
  firstReceiptHash: string;
  lastReceiptHash: string;
  merkleRoot: string;
  receiptRows: readonly StoredReceiptRow[];
  paymentFactsRows: readonly StoredPaymentFactsRow[];
  settlementRows: readonly StoredSettlementRow[];
}

interface TotalsAccumulator {
  asset: string;
  network: string;
  settled: bigint;
  unsettled: bigint;
}

export function createAggregateFromLedger(ledger: ReceiptLedgerReader, options: AggregateLedgerOptions): AggregationArtifacts {
  const computed = computeAggregate(ledger, options.range, options.keyPair.publicKey, options.allowLegacy ?? false);
  const summary = createSignedAggregateSummary({
    schema_version: "1.0",
    aggregate_id: options.aggregateId ?? randomUUID(),
    created_at: (options.createdAt ?? new Date()).toISOString(),
    range: computed.range,
    receipt_count: computed.receiptCount,
    decision_counts: computed.decisionCounts,
    reason_code_counts: computed.reasonCodeCounts,
    invalid_intent_count: computed.invalidIntentCount,
    invalid_policy_count: computed.invalidPolicyCount,
    legacy_unproven_count: computed.legacyUnprovenCount,
    totals: computed.totals,
    first_receipt_hash: computed.firstReceiptHash,
    last_receipt_hash: computed.lastReceiptHash,
    merkle_root: computed.merkleRoot,
    keyPair: options.keyPair
  });

  return {
    summary,
    receiptRows: computed.receiptRows,
    paymentFactsRows: computed.paymentFactsRows,
    settlementRows: computed.settlementRows
  };
}

export function verifyAggregateInLedger(
  ledger: ReceiptLedgerReader,
  summaryInput: unknown,
  publicKey: string
): AggregateVerificationResult {
  const parsed = aggregateSummarySchema.safeParse(summaryInput);
  if (!parsed.success || !verifyAggregateSummary(parsed.data, publicKey)) {
    return fail("SUMMARY_SIGNATURE_INVALID", "Aggregate summary signature verification failed");
  }

  try {
    const computed = computeAggregate(ledger, parsed.data.range, publicKey, parsed.data.legacy_unproven_count > 0);
    const expected = {
      receipt_count: computed.receiptCount,
      decision_counts: computed.decisionCounts,
      reason_code_counts: computed.reasonCodeCounts,
      invalid_intent_count: computed.invalidIntentCount,
      invalid_policy_count: computed.invalidPolicyCount,
      legacy_unproven_count: computed.legacyUnprovenCount,
      totals: computed.totals,
      first_receipt_hash: computed.firstReceiptHash,
      last_receipt_hash: computed.lastReceiptHash,
      merkle_root: computed.merkleRoot
    };
    const actual = {
      receipt_count: parsed.data.receipt_count,
      decision_counts: parsed.data.decision_counts,
      reason_code_counts: parsed.data.reason_code_counts,
      invalid_intent_count: parsed.data.invalid_intent_count,
      invalid_policy_count: parsed.data.invalid_policy_count,
      legacy_unproven_count: parsed.data.legacy_unproven_count,
      totals: parsed.data.totals,
      first_receipt_hash: parsed.data.first_receipt_hash,
      last_receipt_hash: parsed.data.last_receipt_hash,
      merkle_root: parsed.data.merkle_root
    };

    if (canonicalJson(actual) !== canonicalJson(expected)) {
      return fail("TOTALS_MISMATCH", "Aggregate summary does not match ledger records");
    }
  } catch (error) {
    if (error instanceof AggregationError) {
      return fail(error.code, error.message);
    }
    return fail("TOTALS_MISMATCH", error instanceof Error ? error.message : String(error));
  }

  return { valid: true };
}

function computeAggregate(
  ledger: ReceiptLedgerReader,
  range: AggregateRange,
  publicKey: string,
  allowLegacy: boolean
): ComputedAggregate {
  const chain = verifyChain(ledger, publicKey);
  if (!chain.valid) {
    throw new AggregationError("CHAIN_INVALID", chain.error ?? "Receipt chain verification failed");
  }

  const selected = selectReceipts(ledger.listReceiptRows(), range, publicKey);
  const decisionCounts: Record<Decision, number> = { ALLOW: 0, DENY: 0 };
  const reasonCodeCounts = Object.fromEntries(reasonCodes.map((reasonCode) => [reasonCode, 0])) as Record<ReasonCode, number>;
  const totals = new Map<string, TotalsAccumulator>();
  const factsRows: StoredPaymentFactsRow[] = [];
  const settlementRows: StoredSettlementRow[] = [];
  let invalidIntentCount = 0;
  let invalidPolicyCount = 0;
  let legacyUnprovenCount = 0;

  for (const selectedReceipt of selected) {
    const { receipt, row } = selectedReceipt;
    decisionCounts[receipt.decision] += 1;
    reasonCodeCounts[receipt.reason_code] += 1;

    const factsRow = ledger.getPaymentFactsRowByReceiptId(receipt.receipt_id);
    if (!isFactsEligibleReasonCode(receipt.reason_code)) {
      if (factsRow !== null) {
        throw new AggregationError("FACTS_CARDINALITY_INVALID", "Facts-prohibited receipt has payment facts");
      }
      if (receipt.reason_code === "INTENT_INVALID") {
        invalidIntentCount += 1;
      }
      if (receipt.reason_code === "POLICY_INVALID") {
        invalidPolicyCount += 1;
      }
      continue;
    }

    if (factsRow === null) {
      if (!allowLegacy) {
        throw new AggregationError("LEGACY_RECEIPTS_IN_RANGE", "Selected range contains legacy receipt records");
      }
      legacyUnprovenCount += 1;
      continue;
    }

    const facts = parseFacts(factsRow, receipt, row.receiptHash, publicKey);
    factsRows.push(factsRow);
    if (receipt.decision !== "ALLOW") {
      continue;
    }

    const settlementRow = ledger.getSettlementRowByReceiptId(receipt.receipt_id);
    const settlement = settlementRow === null ? null : parseSettlement(settlementRow, receipt, facts, row.receiptHash, publicKey);
    if (settlementRow !== null) {
      settlementRows.push(settlementRow);
    }

    const normalizedNetwork = mapFactsNetwork(facts.network) ?? facts.network;
    const accumulatorKey = `${facts.asset}\u0000${normalizedNetwork}`;
    const accumulator = totals.get(accumulatorKey) ?? {
      asset: facts.asset,
      network: normalizedNetwork,
      settled: 0n,
      unsettled: 0n
    };
    if (settlement === null) {
      accumulator.unsettled += BigInt(facts.amount_base_units);
    } else {
      accumulator.settled += BigInt(facts.amount_base_units);
    }
    totals.set(accumulatorKey, accumulator);
  }

  return {
    range,
    receiptCount: selected.length,
    decisionCounts,
    reasonCodeCounts,
    invalidIntentCount,
    invalidPolicyCount,
    legacyUnprovenCount,
    totals: [...totals.values()]
      .sort((left, right) => compareText(left.asset, right.asset) || compareText(left.network, right.network))
      .map((total) => ({
        asset: total.asset,
        network: total.network,
        settled_base_units: total.settled.toString(),
        unsettled_allow_base_units: total.unsettled.toString()
      })),
    firstReceiptHash: selected[0]?.row.receiptHash ?? throwEmptyRange(),
    lastReceiptHash: selected.at(-1)?.row.receiptHash ?? throwEmptyRange(),
    merkleRoot: merkleRoot(selected.map((selectedReceipt) => selectedReceipt.row.receiptHash)),
    receiptRows: selected.map((selectedReceipt) => selectedReceipt.row),
    paymentFactsRows: factsRows,
    settlementRows
  };
}

function selectReceipts(rows: readonly StoredReceiptRow[], range: AggregateRange, publicKey: string): SelectedReceipt[] {
  const parsedRows = rows.map((row) => ({ row, receipt: parseReceipt(row, publicKey) }));

  if (range.type === "receipt_id") {
    const fromIndex = parsedRows.findIndex((entry) => entry.receipt.receipt_id === range.from_id);
    const toIndex = parsedRows.findIndex((entry) => entry.receipt.receipt_id === range.to_id);
    if (fromIndex === -1 || toIndex === -1) {
      throw new AggregationError("RECEIPT_NOT_FOUND", "Range endpoint receipt was not found");
    }
    if (fromIndex > toIndex) {
      throw new AggregationError("INVALID_RANGE", "Receipt range start occurs after range end");
    }
    return parsedRows.slice(fromIndex, toIndex + 1);
  }

  const since = Date.parse(range.since);
  const until = Date.parse(range.until);
  if (!Number.isFinite(since) || !Number.isFinite(until) || since >= until) {
    throw new AggregationError("INVALID_RANGE", "Time range is invalid");
  }

  return parsedRows.filter((entry) => {
    const timestamp = Date.parse(entry.receipt.timestamp);
    return timestamp >= since && timestamp < until;
  });
}

function parseReceipt(row: StoredReceiptRow, publicKey: string): Receipt {
  let parsedJson: unknown;
  try {
    parsedJson = JSON.parse(row.receiptJson);
  } catch {
    throw new AggregationError("RECEIPT_SIGNATURE_INVALID", "Receipt JSON is not parseable");
  }
  const parsed = receiptSchema.safeParse(parsedJson);
  if (!parsed.success || receiptHash(parsed.data) !== row.receiptHash || !verifyReceipt(parsed.data, publicKey)) {
    throw new AggregationError("RECEIPT_SIGNATURE_INVALID", "Receipt signature verification failed");
  }
  return parsed.data;
}

function parseFacts(row: StoredPaymentFactsRow, receipt: Receipt, receiptHashValue: string, publicKey: string): PaymentFacts {
  let parsedJson: unknown;
  try {
    parsedJson = JSON.parse(row.factsJson);
  } catch {
    throw new AggregationError("FACTS_SIGNATURE_INVALID", "Payment facts JSON is not parseable");
  }
  const parsed = paymentFactsSchema.safeParse(parsedJson);
  if (
    !parsed.success ||
    !verifyPaymentFacts(parsed.data, publicKey) ||
    parsed.data.receipt_id !== receipt.receipt_id ||
    parsed.data.receipt_hash !== receiptHashValue
  ) {
    throw new AggregationError("FACTS_SIGNATURE_INVALID", "Payment facts signature verification failed");
  }
  return parsed.data;
}

function parseSettlement(
  row: StoredSettlementRow,
  receipt: Receipt,
  facts: PaymentFacts,
  receiptHashValue: string,
  publicKey: string
): Settlement {
  let parsedJson: unknown;
  try {
    parsedJson = JSON.parse(row.settlementJson);
  } catch {
    throw new AggregationError("SETTLEMENT_SIGNATURE_INVALID", "Settlement JSON is not parseable");
  }
  const parsed = settlementSchema.safeParse(parsedJson);
  if (!parsed.success || !verifySettlement(parsed.data, publicKey)) {
    throw new AggregationError("SETTLEMENT_SIGNATURE_INVALID", "Settlement signature verification failed");
  }
  if (parsed.data.receipt_id !== receipt.receipt_id || parsed.data.receipt_hash !== receiptHashValue) {
    throw new AggregationError("SETTLEMENT_BINDING_INVALID", "Settlement does not bind to its receipt");
  }
  const expectedNetwork = mapFactsNetwork(facts.network);
  if (expectedNetwork === null || parsed.data.network !== expectedNetwork) {
    throw new AggregationError("SETTLEMENT_NETWORK_MISMATCH", "Settlement network does not match payment facts");
  }
  return parsed.data;
}

function compareText(left: string, right: string): number {
  if (left < right) {
    return -1;
  }
  if (left > right) {
    return 1;
  }
  return 0;
}

function throwEmptyRange(): never {
  throw new AggregationError("EMPTY_RANGE", "Selected range contains no receipts");
}

function fail(code: AggregationErrorCode, error: string): AggregateVerificationResult {
  return { valid: false, code, error };
}
