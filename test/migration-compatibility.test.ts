import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import Database from "better-sqlite3";
import { afterEach, describe, expect, it } from "vitest";

import {
  assertJsonValue,
  canonicalReceiptJson,
  canonicalSha256Hex,
  createSignedReceipt,
  evaluateAndRecord,
  generateEd25519KeyPair,
  receiptHash,
  SqliteReceiptLedger,
  verifyChain
} from "../src/index.js";

const tempDirs: string[] = [];

afterEach(() => {
  for (const tempDir of tempDirs.splice(0)) {
    rmSync(tempDir, { force: true, recursive: true });
  }
});

function tempDbPath(): string {
  const tempDir = mkdtempSync(join(tmpdir(), "x402-spend-receipt-v01-"));
  tempDirs.push(tempDir);
  return join(tempDir, "legacy.sqlite");
}

describe("v0.1.1 compatibility", () => {
  it("opens a v0.1 receipt ledger by adding tables without changing receipt rows", () => {
    const dbPath = tempDbPath();
    const keyPair = generateEd25519KeyPair();
    const receipt = createSignedReceipt({
      receiptId: "00000000-0000-4000-8000-000000000080",
      timestamp: "2026-06-10T22:00:00.000Z",
      agentUrn: "urn:agent:demo",
      intentDigest: "a".repeat(64),
      policyDigest: "b".repeat(64),
      decision: "ALLOW",
      reasonCode: "ALLOWED",
      prevReceiptHash: null,
      keyPair
    });
    const legacy = new Database(dbPath);
    legacy.exec(`
      CREATE TABLE receipts (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        receipt_id TEXT NOT NULL UNIQUE,
        receipt_json TEXT NOT NULL,
        receipt_hash TEXT NOT NULL UNIQUE,
        decision TEXT NOT NULL,
        reason_code TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        agent_urn TEXT NOT NULL,
        endpoint_url TEXT,
        amount_base_units TEXT
      );
    `);
    legacy
      .prepare(
        "INSERT INTO receipts (receipt_id, receipt_json, receipt_hash, decision, reason_code, timestamp, agent_urn, endpoint_url, amount_base_units) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
      )
      .run(
        receipt.receipt_id,
        canonicalReceiptJson(receipt),
        receiptHash(receipt),
        receipt.decision,
        receipt.reason_code,
        receipt.timestamp,
        receipt.agent_urn,
        "https://api.example.com/metered",
        "100"
      );
    const beforeRows = legacy.prepare("SELECT * FROM receipts ORDER BY sequence ASC").all();
    const beforeTables = legacy
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name ASC")
      .all() as Array<{ name: string }>;
    legacy.close();

    const migrated = new SqliteReceiptLedger(dbPath);
    expect(verifyChain(migrated, keyPair.publicKey)).toEqual({ valid: true });
    migrated.close();

    const inspected = new Database(dbPath);
    const afterRows = inspected.prepare("SELECT * FROM receipts ORDER BY sequence ASC").all();
    const afterTables = inspected
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name ASC")
      .all() as Array<{ name: string }>;
    inspected.close();

    expect(afterRows).toEqual(beforeRows);
    expect(afterTables.map((table) => table.name)).toEqual(expect.arrayContaining(beforeTables.map((table) => table.name)));
    expect(afterTables.map((table) => table.name)).toEqual(expect.arrayContaining(["payment_facts", "settlements"]));
  });

  it("keeps omitted budget mode receipt bytes identical to the v0.1 receipt construction", () => {
    const ledger = new SqliteReceiptLedger(tempDbPath());
    const keyPair = generateEd25519KeyPair();
    const now = new Date("2026-06-10T22:00:00.000Z");
    const intent = {
      method: "x402",
      endpoint_url: "https://api.example.com/metered",
      pay_to: "0xabc123",
      asset: "USDC",
      network: "base",
      amount_base_units: "100",
      agent_urn: "urn:agent:demo"
    };
    const policy = {
      max_per_payment_base_units: "100",
      session_budget_base_units: "1000",
      pay_to_allowlist: ["0xabc123"],
      endpoint_host_allowlist: ["api.example.com"],
      repeat_payment_rule: { max_repeats: 10, window_seconds: 60 }
    };
    const receiptId = "00000000-0000-4000-8000-000000000081";
    const expected = createSignedReceipt({
      receiptId,
      timestamp: now.toISOString(),
      agentUrn: intent.agent_urn,
      intentDigest: canonicalSha256Hex(assertJsonValue(intent)),
      policyDigest: canonicalSha256Hex(assertJsonValue(policy)),
      decision: "ALLOW",
      reasonCode: "ALLOWED",
      prevReceiptHash: null,
      keyPair
    });

    const actual = evaluateAndRecord(intent, policy, {
      ledger,
      keyPair,
      now,
      receiptIdFactory: () => receiptId,
      factsIdFactory: () => "00000000-0000-4000-8000-000000000082"
    });

    expect(actual.receipt).toEqual(expected);
    expect(JSON.stringify(actual.receipt)).toBe(JSON.stringify(expected));
    expect(ledger.listPaymentFactsRows()).toHaveLength(1);
    ledger.close();
  });
});
