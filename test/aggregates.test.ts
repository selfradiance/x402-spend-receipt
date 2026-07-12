import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  AggregationError,
  createAggregateFromLedger,
  createSignedAggregateSummary,
  createSignedSettlement,
  createSignedReceipt,
  evaluateAndRecord,
  generateEd25519KeyPair,
  merkleRoot,
  receiptHash,
  SqliteReceiptLedger,
  verifyAggregateInLedger,
  verifyAggregateSummary
} from "../src/index.js";

const hashes = ["0", "1", "2", "3", "4", "5"].map((character) => character.repeat(64));
const tempDirs: string[] = [];

const validIntent = {
  method: "x402",
  endpoint_url: "https://api.example.com/metered",
  pay_to: "0xabc123",
  asset: "USDC",
  network: "base",
  amount_base_units: "100",
  agent_urn: "urn:agent:demo"
};

const validPolicy = {
  max_per_payment_base_units: "100",
  session_budget_base_units: "1000",
  pay_to_allowlist: ["0xabc123"],
  endpoint_host_allowlist: ["api.example.com"],
  repeat_payment_rule: {
    max_repeats: 10,
    window_seconds: 60
  }
};

afterEach(() => {
  for (const tempDir of tempDirs.splice(0)) {
    rmSync(tempDir, { force: true, recursive: true });
  }
});

function tempDbPath(): string {
  const tempDir = mkdtempSync(join(tmpdir(), "x402-spend-receipt-aggregate-"));
  tempDirs.push(tempDir);
  return join(tempDir, "ledger.sqlite");
}

describe("aggregate primitives", () => {
  it("matches RFC 6962 Merkle vectors for one through six leaves", () => {
    expect(merkleRoot(hashes.slice(0, 1))).toBe("7f9c9e31ac8256ca2f258583df262dbc7d6f68f2a03043d5c99a4ae5a7396ce9");
    expect(merkleRoot(hashes.slice(0, 2))).toBe("8ab671c69294e69917042ed794e5ea9dda18710ca307a65b986226344b87552a");
    expect(merkleRoot(hashes.slice(0, 3))).toBe("cfdd57c49cf0b23df41b9ff2fce70eed9d15fd0242a185dbdb5b918f8b140cce");
    expect(merkleRoot(hashes.slice(0, 5))).toBe("e68425ce96c5fff3a5f4ee6d49a0c3c84088038a9f27a568ca501ce69507c345");
    expect(merkleRoot(hashes.slice(0, 6))).toBe("65d68110552cf25209ec8a740bda6795af11a88fe382b1fe0c0e4fb2a3066437");
  });

  it("signs aggregate summaries and rejects altered fields", () => {
    const keyPair = generateEd25519KeyPair();
    const summary = createSignedAggregateSummary({
      schema_version: "1.0",
      aggregate_id: "00000000-0000-4000-8000-000000000030",
      created_at: "2026-06-10T22:00:00.000Z",
      range: {
        type: "receipt_id",
        from_id: "00000000-0000-4000-8000-000000000031",
        to_id: "00000000-0000-4000-8000-000000000031"
      },
      receipt_count: 1,
      decision_counts: { ALLOW: 1, DENY: 0 },
      reason_code_counts: {
        ALLOWED: 1,
        AMOUNT_EXCEEDS_PER_PAYMENT_MAX: 0,
        SESSION_BUDGET_EXCEEDED: 0,
        PAY_TO_NOT_ALLOWED: 0,
        HOST_NOT_ALLOWED: 0,
        REPEAT_PAYMENT_LOOP: 0,
        INTENT_INVALID: 0,
        POLICY_INVALID: 0
      },
      invalid_intent_count: 0,
      invalid_policy_count: 0,
      legacy_unproven_count: 0,
      totals: [
        {
          asset: "USDC",
          network: "base",
          settled_base_units: "0",
          unsettled_allow_base_units: "100"
        }
      ],
      first_receipt_hash: hashes[0] ?? "",
      last_receipt_hash: hashes[0] ?? "",
      merkle_root: merkleRoot(hashes.slice(0, 1)),
      keyPair
    });

    expect(verifyAggregateSummary(summary, keyPair.publicKey)).toBe(true);
    expect(verifyAggregateSummary({ ...summary, receipt_count: 2 }, keyPair.publicKey)).toBe(false);
    expect(verifyAggregateSummary({ ...summary, totals: [] }, keyPair.publicKey)).toBe(false);
  });

  it("aggregates verified receipt facts and settlements without mixing units", () => {
    const ledger = new SqliteReceiptLedger(tempDbPath());
    const keyPair = generateEd25519KeyPair();
    const receiptIds = ["00000000-0000-4000-8000-000000000040", "00000000-0000-4000-8000-000000000041"];
    const factsIds = ["00000000-0000-4000-8000-000000000042", "00000000-0000-4000-8000-000000000043"];
    let receiptIndex = 0;
    let factsIndex = 0;

    const first = evaluateAndRecord(validIntent, validPolicy, {
      ledger,
      keyPair,
      now: new Date("2026-06-10T22:00:00.000Z"),
      receiptIdFactory: () => receiptIds[receiptIndex++] ?? "",
      factsIdFactory: () => factsIds[factsIndex++] ?? ""
    });
    const second = evaluateAndRecord({ ...validIntent, asset: "EURC", amount_base_units: "50" }, { ...validPolicy, max_per_payment_base_units: "100" }, {
      ledger,
      keyPair,
      now: new Date("2026-06-10T22:01:00.000Z"),
      receiptIdFactory: () => receiptIds[receiptIndex++] ?? "",
      factsIdFactory: () => factsIds[factsIndex++] ?? ""
    });
    if (first.receipt === null || second.receipt === null) {
      throw new Error("Expected receipts");
    }
    ledger.appendSettlement(
      createSignedSettlement({
        settlementId: "00000000-0000-4000-8000-000000000044",
        timestamp: "2026-06-10T22:02:00.000Z",
        receiptId: first.receipt.receipt_id,
        receiptHash: receiptHash(first.receipt),
        txHash: `0x${"a".repeat(64)}`,
        network: "eip155:8453",
        keyPair
      })
    );

    const aggregate = createAggregateFromLedger(ledger, {
      range: {
        type: "receipt_id",
        from_id: first.receipt.receipt_id,
        to_id: second.receipt.receipt_id
      },
      aggregateId: "00000000-0000-4000-8000-000000000045",
      createdAt: new Date("2026-06-10T22:03:00.000Z"),
      keyPair
    });

    expect(aggregate.summary.receipt_count).toBe(2);
    expect(aggregate.summary.decision_counts).toEqual({ ALLOW: 2, DENY: 0 });
    expect(aggregate.summary.totals).toEqual([
      {
        asset: "EURC",
        network: "eip155:8453",
        settled_base_units: "0",
        unsettled_allow_base_units: "50"
      },
      {
        asset: "USDC",
        network: "eip155:8453",
        settled_base_units: "100",
        unsettled_allow_base_units: "0"
      }
    ]);
    expect(verifyAggregateInLedger(ledger, aggregate.summary, keyPair.publicKey)).toEqual({ valid: true });
    expect(verifyAggregateInLedger(ledger, { ...aggregate.summary, receipt_count: 3 }, keyPair.publicKey)).toMatchObject({
      valid: false,
      code: "SUMMARY_SIGNATURE_INVALID"
    });

    ledger.close();
  });

  it("rejects legacy receipts unless the caller explicitly allows unproven totals", () => {
    const ledger = new SqliteReceiptLedger(tempDbPath());
    const keyPair = generateEd25519KeyPair();
    const legacyReceipt = createSignedReceipt({
      receiptId: "00000000-0000-4000-8000-000000000046",
      timestamp: "2026-06-10T22:00:00.000Z",
      agentUrn: "urn:agent:demo",
      intentDigest: "a".repeat(64),
      policyDigest: "b".repeat(64),
      decision: "ALLOW",
      reasonCode: "ALLOWED",
      prevReceiptHash: null,
      keyPair
    });
    ledger.appendReceipt(legacyReceipt, { endpointUrl: "https://api.example.com/metered", amountBaseUnits: "100" });
    const range = {
      type: "receipt_id" as const,
      from_id: legacyReceipt.receipt_id,
      to_id: legacyReceipt.receipt_id
    };

    expect(() => createAggregateFromLedger(ledger, { range, keyPair })).toThrowError(
      expect.objectContaining<Partial<AggregationError>>({ code: "LEGACY_RECEIPTS_IN_RANGE" })
    );
    const allowed = createAggregateFromLedger(ledger, { range, allowLegacy: true, keyPair });
    expect(allowed.summary.legacy_unproven_count).toBe(1);
    expect(allowed.summary.totals).toEqual([]);

    ledger.close();
  });
});
