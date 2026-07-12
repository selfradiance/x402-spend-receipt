import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  createSignedPaymentFacts,
  createSignedReceipt,
  createSignedSettlement,
  evaluateAndRecord,
  generateEd25519KeyPair,
  receiptHash,
  SqliteReceiptLedger,
  verifyPaymentFacts,
  verifySettlement
} from "../src/index.js";

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

const tempDirs: string[] = [];

afterEach(() => {
  for (const tempDir of tempDirs.splice(0)) {
    rmSync(tempDir, { force: true, recursive: true });
  }
});

function tempDbPath(): string {
  const tempDir = mkdtempSync(join(tmpdir(), "x402-spend-receipt-facts-"));
  tempDirs.push(tempDir);
  return join(tempDir, "ledger.sqlite");
}

function ids(prefix: string): () => string {
  let next = 0;
  return () => {
    const suffix = String(next).padStart(12, "0");
    next += 1;
    return `00000000-0000-4000-8000-${prefix}${suffix.slice(prefix.length)}`;
  };
}

describe("payment facts and settlements", () => {
  it("signs payment facts and detects tampering", () => {
    const keyPair = generateEd25519KeyPair();
    const facts = createSignedPaymentFacts({
      factsId: "00000000-0000-4000-8000-000000000010",
      timestamp: "2026-06-10T22:00:00.000Z",
      receiptId: "00000000-0000-4000-8000-000000000011",
      receiptHash: "a".repeat(64),
      amountBaseUnits: "100",
      asset: "USDC",
      network: "base",
      payTo: "0xabc123",
      keyPair
    });

    expect(verifyPaymentFacts(facts, keyPair.publicKey)).toBe(true);
    expect(verifyPaymentFacts({ ...facts, amount_base_units: "101" }, keyPair.publicKey)).toBe(false);
    expect(verifyPaymentFacts({ ...facts, receipt_hash: "b".repeat(64) }, keyPair.publicKey)).toBe(false);
  });

  it("writes facts atomically with every facts-eligible receipt", () => {
    const ledger = new SqliteReceiptLedger(tempDbPath());
    const keyPair = generateEd25519KeyPair();

    const result = evaluateAndRecord(validIntent, validPolicy, {
      ledger,
      keyPair,
      now: new Date("2026-06-10T22:00:00.000Z"),
      receiptIdFactory: () => "00000000-0000-4000-8000-000000000012",
      factsIdFactory: () => "00000000-0000-4000-8000-000000000013"
    });

    expect(result.decision).toBe("ALLOW");
    expect(result.receipt).not.toBeNull();
    if (result.receipt === null) {
      throw new Error("Expected receipt");
    }

    const factsRow = ledger.getPaymentFactsRowByReceiptId(result.receipt.receipt_id);
    expect(factsRow).not.toBeNull();
    expect(factsRow?.receiptHash).toBe(receiptHash(result.receipt));
    expect(verifyPaymentFacts(JSON.parse(factsRow?.factsJson ?? "null"), keyPair.publicKey)).toBe(true);

    ledger.close();
  });

  it("does not write facts for invalid intent or invalid policy receipts", () => {
    const ledger = new SqliteReceiptLedger(tempDbPath());
    const keyPair = generateEd25519KeyPair();
    const nextReceiptId = ids("0000000000");
    const nextFactsId = ids("0000000000");

    const invalidIntent = evaluateAndRecord({ ...validIntent, amount_base_units: "1.5" }, validPolicy, {
      ledger,
      keyPair,
      now: new Date("2026-06-10T22:00:00.000Z"),
      receiptIdFactory: nextReceiptId,
      factsIdFactory: nextFactsId
    });
    const invalidPolicy = evaluateAndRecord(validIntent, { ...validPolicy, max_per_payment_base_units: "-1" }, {
      ledger,
      keyPair,
      now: new Date("2026-06-10T22:01:00.000Z"),
      receiptIdFactory: nextReceiptId,
      factsIdFactory: nextFactsId
    });

    expect(invalidIntent.reasonCode).toBe("INTENT_INVALID");
    expect(invalidPolicy.reasonCode).toBe("POLICY_INVALID");
    expect(invalidIntent.receipt).not.toBeNull();
    expect(invalidPolicy.receipt).not.toBeNull();
    expect(ledger.listPaymentFactsRows()).toHaveLength(0);

    ledger.close();
  });

  it("rolls back the receipt when its facts record cannot be bound", () => {
    const ledger = new SqliteReceiptLedger(tempDbPath());
    const keyPair = generateEd25519KeyPair();
    const receipt = createSignedReceipt({
      receiptId: "00000000-0000-4000-8000-000000000014",
      timestamp: "2026-06-10T22:00:00.000Z",
      agentUrn: "urn:agent:demo",
      intentDigest: "a".repeat(64),
      policyDigest: "b".repeat(64),
      decision: "ALLOW",
      reasonCode: "ALLOWED",
      prevReceiptHash: null,
      keyPair
    });
    const facts = createSignedPaymentFacts({
      factsId: "00000000-0000-4000-8000-000000000015",
      timestamp: "2026-06-10T22:00:00.000Z",
      receiptId: receipt.receipt_id,
      receiptHash: "c".repeat(64),
      amountBaseUnits: "100",
      asset: "USDC",
      network: "base",
      payTo: "0xabc123",
      keyPair
    });

    expect(() => ledger.appendReceipt(receipt, { endpointUrl: null, amountBaseUnits: null }, facts)).toThrow(
      "Payment facts do not bind"
    );
    expect(ledger.listReceiptRows()).toHaveLength(0);
    expect(ledger.listPaymentFactsRows()).toHaveLength(0);

    ledger.close();
  });

  it("signs settlements, binds them to receipts, and enforces unique links", () => {
    const ledger = new SqliteReceiptLedger(tempDbPath());
    const keyPair = generateEd25519KeyPair();
    const nextReceiptId = ids("0000000000");
    const nextFactsId = ids("0000000000");

    const first = evaluateAndRecord(validIntent, validPolicy, {
      ledger,
      keyPair,
      now: new Date("2026-06-10T22:00:00.000Z"),
      receiptIdFactory: nextReceiptId,
      factsIdFactory: nextFactsId
    });
    const second = evaluateAndRecord(validIntent, validPolicy, {
      ledger,
      keyPair,
      now: new Date("2026-06-10T22:01:00.000Z"),
      receiptIdFactory: nextReceiptId,
      factsIdFactory: nextFactsId
    });
    if (first.receipt === null || second.receipt === null) {
      throw new Error("Expected receipts");
    }

    const settlement = createSignedSettlement({
      settlementId: "00000000-0000-4000-8000-000000000016",
      timestamp: "2026-06-10T22:02:00.000Z",
      receiptId: first.receipt.receipt_id,
      receiptHash: receiptHash(first.receipt),
      txHash: `0x${"a".repeat(64)}`,
      network: "eip155:8453",
      keyPair
    });

    expect(verifySettlement(settlement, keyPair.publicKey)).toBe(true);
    expect(verifySettlement({ ...settlement, tx_hash: `0x${"b".repeat(64)}` }, keyPair.publicKey)).toBe(false);
    ledger.appendSettlement(settlement);
    expect(ledger.getSettlementRowByReceiptId(first.receipt.receipt_id)?.txHash).toBe(settlement.tx_hash);
    expect(() => ledger.appendSettlement(settlement)).toThrow();

    const reusedTx = createSignedSettlement({
      settlementId: "00000000-0000-4000-8000-000000000017",
      timestamp: "2026-06-10T22:03:00.000Z",
      receiptId: second.receipt.receipt_id,
      receiptHash: receiptHash(second.receipt),
      txHash: settlement.tx_hash,
      network: settlement.network,
      keyPair
    });
    expect(() => ledger.appendSettlement(reusedTx)).toThrow();

    ledger.close();
  });
});
