import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import Database from "better-sqlite3";
import { afterEach, describe, expect, it } from "vitest";

import {
  evaluateAndRecord,
  generateEd25519KeyPair,
  SqliteReceiptLedger,
  verifyChain,
  verifyReceipt,
  type Ed25519KeyPair,
  type ReceiptLedgerWriter
} from "../src/index.js";

const now = new Date("2026-06-10T22:00:00.000Z");

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
  const tempDir = mkdtempSync(join(tmpdir(), "x402-spend-receipt-"));
  tempDirs.push(tempDir);
  return join(tempDir, "ledger.db");
}

function receiptIdFactory(): () => string {
  let nextId = 0;

  return () => {
    const suffix = String(nextId).padStart(12, "0");
    nextId += 1;
    return `00000000-0000-4000-8000-${suffix}`;
  };
}

function recordAllow(
  ledger: SqliteReceiptLedger,
  keyPair: Ed25519KeyPair,
  nextReceiptId = receiptIdFactory()
) {
  return evaluateAndRecord(validIntent, validPolicy, {
    ledger,
    keyPair,
    now,
    receiptIdFactory: nextReceiptId
  });
}

describe("signing and ledger receipts", () => {
  it("verifies a receipt signature with the correct key and rejects a wrong key", () => {
    const ledger = new SqliteReceiptLedger(tempDbPath());
    const keyPair = generateEd25519KeyPair();
    const wrongKeyPair = generateEd25519KeyPair();

    const result = recordAllow(ledger, keyPair);

    expect(result.decision).toBe("ALLOW");
    expect(result.receipt).not.toBeNull();
    if (result.receipt === null) {
      throw new Error("Expected a receipt");
    }
    expect(verifyReceipt(result.receipt, keyPair.publicKey)).toBe(true);
    expect(verifyReceipt(result.receipt, wrongKeyPair.publicKey)).toBe(false);

    ledger.close();
  });

  it("fails chain verification after a stored receipt row is tampered", () => {
    const dbPath = tempDbPath();
    const ledger = new SqliteReceiptLedger(dbPath);
    const keyPair = generateEd25519KeyPair();
    const nextReceiptId = receiptIdFactory();

    expect(recordAllow(ledger, keyPair, nextReceiptId).decision).toBe("ALLOW");
    expect(recordAllow(ledger, keyPair, nextReceiptId).decision).toBe("ALLOW");
    expect(verifyChain(ledger, keyPair.publicKey)).toEqual({ valid: true });

    const db = new Database(dbPath);
    const row = db
      .prepare("SELECT sequence, receipt_json FROM receipts ORDER BY sequence ASC LIMIT 1")
      .get() as { sequence: number; receipt_json: string };
    const receipt = JSON.parse(row.receipt_json) as { agent_urn: string };
    receipt.agent_urn = "urn:agent:tampered";
    db.prepare("UPDATE receipts SET receipt_json = ? WHERE sequence = ?").run(JSON.stringify(receipt), row.sequence);
    db.close();

    const verification = verifyChain(ledger, keyPair.publicKey);
    expect(verification.valid).toBe(false);
    expect(verification.error).toBe("Stored receipt hash does not match receipt bytes");

    ledger.close();
  });

  it("uses the SQLite ledger for session budget accumulation across prior ALLOW receipts", () => {
    const dbPath = tempDbPath();
    const keyPair = generateEd25519KeyPair();
    const nextReceiptId = receiptIdFactory();
    const budgetPolicy = {
      ...validPolicy,
      session_budget_base_units: "250"
    };
    const firstLedger = new SqliteReceiptLedger(dbPath);

    const first = evaluateAndRecord(validIntent, budgetPolicy, {
      ledger: firstLedger,
      keyPair,
      now,
      receiptIdFactory: nextReceiptId
    });
    const second = evaluateAndRecord(validIntent, budgetPolicy, {
      ledger: firstLedger,
      keyPair,
      now,
      receiptIdFactory: nextReceiptId
    });
    firstLedger.close();

    const reopenedLedger = new SqliteReceiptLedger(dbPath);
    const third = evaluateAndRecord(validIntent, budgetPolicy, {
      ledger: reopenedLedger,
      keyPair,
      now,
      receiptIdFactory: nextReceiptId
    });

    expect(first.reasonCode).toBe("ALLOWED");
    expect(second.reasonCode).toBe("ALLOWED");
    expect(third).toMatchObject({
      decision: "DENY",
      reasonCode: "SESSION_BUDGET_EXCEEDED"
    });
    expect(reopenedLedger.listAllowedReceipts()).toHaveLength(2);

    reopenedLedger.close();
  });

  it("uses the SQLite ledger for repeat-loop detection", () => {
    const ledger = new SqliteReceiptLedger(tempDbPath());
    const keyPair = generateEd25519KeyPair();
    const nextReceiptId = receiptIdFactory();
    const repeatPolicy = {
      ...validPolicy,
      session_budget_base_units: "1000",
      repeat_payment_rule: {
        max_repeats: 1,
        window_seconds: 60
      }
    };

    const first = evaluateAndRecord(validIntent, repeatPolicy, {
      ledger,
      keyPair,
      now,
      receiptIdFactory: nextReceiptId
    });
    const second = evaluateAndRecord(validIntent, repeatPolicy, {
      ledger,
      keyPair,
      now,
      receiptIdFactory: nextReceiptId
    });
    const third = evaluateAndRecord(validIntent, repeatPolicy, {
      ledger,
      keyPair,
      now,
      receiptIdFactory: nextReceiptId
    });

    expect(first.reasonCode).toBe("ALLOWED");
    expect(second.reasonCode).toBe("ALLOWED");
    expect(third).toMatchObject({
      decision: "DENY",
      reasonCode: "REPEAT_PAYMENT_LOOP"
    });

    ledger.close();
  });

  it("denies instead of allowing when receipt persistence fails", () => {
    const keyPair = generateEd25519KeyPair();
    const failingLedger: ReceiptLedgerWriter = {
      getLastReceiptHash: () => null,
      getReceiptRowById: () => null,
      listAllowedReceipts: () => [],
      listReceiptRows: () => [],
      appendReceipt: () => {
        throw new Error("disk full");
      }
    };

    const result = evaluateAndRecord(validIntent, validPolicy, {
      ledger: failingLedger,
      keyPair,
      now,
      receiptIdFactory: receiptIdFactory()
    });

    expect(result.decision).toBe("DENY");
    expect(result.receipt).toBeNull();
  });
});
