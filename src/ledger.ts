import Database from "better-sqlite3";

import { canonicalReceiptJson, receiptHash } from "./receipts.js";
import { type Receipt } from "./schemas.js";
import { type AllowedReceiptHistoryEntry, type ReceiptHistoryReader } from "./policy.js";

export interface ReceiptLedgerMetadata {
  endpointUrl: string | null;
  amountBaseUnits: string | null;
}

export interface StoredReceiptRow {
  sequence: number;
  receiptId: string;
  receiptJson: string;
  receiptHash: string;
}

export interface ReceiptLedgerReader extends ReceiptHistoryReader {
  getLastReceiptHash(): string | null;
  getReceiptRowById(receiptId: string): StoredReceiptRow | null;
  listReceiptRows(): readonly StoredReceiptRow[];
}

export interface ReceiptLedgerWriter extends ReceiptLedgerReader {
  appendReceipt(receipt: Receipt, metadata: ReceiptLedgerMetadata): void;
}

interface LastHashRow {
  receipt_hash: string;
}

interface AllowedHistoryRow {
  endpoint_url: string;
  amount_base_units: string;
  timestamp: string;
}

interface StoredReceiptDbRow {
  sequence: number;
  receipt_id: string;
  receipt_json: string;
  receipt_hash: string;
}

export class SqliteReceiptLedger implements ReceiptLedgerWriter {
  private readonly db: Database.Database;

  constructor(dbPath: string) {
    this.db = new Database(dbPath);
    this.initialize();
  }

  close(): void {
    this.db.close();
  }

  getLastReceiptHash(): string | null {
    const row = this.db
      .prepare("SELECT receipt_hash FROM receipts ORDER BY sequence DESC LIMIT 1")
      .get() as LastHashRow | undefined;
    return row?.receipt_hash ?? null;
  }

  appendReceipt(receipt: Receipt, metadata: ReceiptLedgerMetadata): void {
    const append = this.db.transaction(() => {
      const expectedPreviousHash = this.getLastReceiptHash();
      if (receipt.prev_receipt_hash !== expectedPreviousHash) {
        throw new Error("Receipt previous hash does not match ledger tip");
      }

      this.db
        .prepare(
          `INSERT INTO receipts (
            receipt_id,
            receipt_json,
            receipt_hash,
            decision,
            reason_code,
            timestamp,
            agent_urn,
            endpoint_url,
            amount_base_units
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .run(
          receipt.receipt_id,
          canonicalReceiptJson(receipt),
          receiptHash(receipt),
          receipt.decision,
          receipt.reason_code,
          receipt.timestamp,
          receipt.agent_urn,
          metadata.endpointUrl,
          metadata.amountBaseUnits
        );
    });

    append();
  }

  getReceiptRowById(receiptId: string): StoredReceiptRow | null {
    const row = this.db
      .prepare("SELECT sequence, receipt_id, receipt_json, receipt_hash FROM receipts WHERE receipt_id = ?")
      .get(receiptId) as StoredReceiptDbRow | undefined;

    if (row === undefined) {
      return null;
    }

    return {
      sequence: row.sequence,
      receiptId: row.receipt_id,
      receiptJson: row.receipt_json,
      receiptHash: row.receipt_hash
    };
  }

  listAllowedReceipts(): readonly AllowedReceiptHistoryEntry[] {
    const rows = this.db
      .prepare(
        `SELECT endpoint_url, amount_base_units, timestamp
         FROM receipts
         WHERE decision = 'ALLOW'
           AND endpoint_url IS NOT NULL
           AND amount_base_units IS NOT NULL
         ORDER BY sequence ASC`
      )
      .all() as AllowedHistoryRow[];

    return rows.map((row) => ({
      endpoint_url: row.endpoint_url,
      amount_base_units: row.amount_base_units,
      timestamp: row.timestamp
    }));
  }

  listReceiptRows(): readonly StoredReceiptRow[] {
    const rows = this.db
      .prepare("SELECT sequence, receipt_id, receipt_json, receipt_hash FROM receipts ORDER BY sequence ASC")
      .all() as StoredReceiptDbRow[];

    return rows.map((row) => ({
      sequence: row.sequence,
      receiptId: row.receipt_id,
      receiptJson: row.receipt_json,
      receiptHash: row.receipt_hash
    }));
  }

  private initialize(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS receipts (
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
  }
}
