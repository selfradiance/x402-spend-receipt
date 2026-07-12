import Database from "better-sqlite3";

import { canonicalPaymentFactsJson } from "./facts.js";
import { canonicalReceiptJson, receiptHash } from "./receipts.js";
import { canonicalSettlementJson } from "./settlements.js";
import { type PaymentFacts, type Receipt, type Settlement } from "./schemas.js";
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

export interface StoredPaymentFactsRow {
  factsId: string;
  receiptId: string;
  receiptHash: string;
  factsJson: string;
}

export interface StoredSettlementRow {
  settlementId: string;
  receiptId: string;
  receiptHash: string;
  network: string;
  txHash: string;
  settlementJson: string;
}

export interface ReceiptLedgerReader extends ReceiptHistoryReader {
  getLastReceiptHash(): string | null;
  getReceiptRowById(receiptId: string): StoredReceiptRow | null;
  listReceiptRows(): readonly StoredReceiptRow[];
  getPaymentFactsRowByReceiptId(receiptId: string): StoredPaymentFactsRow | null;
  listPaymentFactsRows(): readonly StoredPaymentFactsRow[];
  getSettlementRowByReceiptId(receiptId: string): StoredSettlementRow | null;
  listSettlementRows(): readonly StoredSettlementRow[];
}

export interface ReceiptLedgerWriter extends ReceiptLedgerReader {
  appendReceipt(receipt: Receipt, metadata: ReceiptLedgerMetadata, paymentFacts?: PaymentFacts): void;
  appendSettlement(settlement: Settlement): void;
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

interface StoredPaymentFactsDbRow {
  facts_id: string;
  receipt_id: string;
  receipt_hash: string;
  facts_json: string;
}

interface StoredSettlementDbRow {
  settlement_id: string;
  receipt_id: string;
  receipt_hash: string;
  network: string;
  tx_hash: string;
  settlement_json: string;
}

export class SqliteReceiptLedger implements ReceiptLedgerWriter {
  private readonly db: Database.Database;

  constructor(dbPath: string) {
    this.db = new Database(dbPath);
    this.db.pragma("foreign_keys = ON");
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

  appendReceipt(receipt: Receipt, metadata: ReceiptLedgerMetadata, paymentFacts?: PaymentFacts): void {
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

      if (paymentFacts !== undefined) {
        const actualReceiptHash = receiptHash(receipt);
        if (paymentFacts.receipt_id !== receipt.receipt_id || paymentFacts.receipt_hash !== actualReceiptHash) {
          throw new Error("Payment facts do not bind to the receipt being appended");
        }

        this.db
          .prepare(
            `INSERT INTO payment_facts (
              facts_id,
              receipt_id,
              receipt_hash,
              facts_json,
              timestamp
            ) VALUES (?, ?, ?, ?, ?)`
          )
          .run(
            paymentFacts.facts_id,
            paymentFacts.receipt_id,
            paymentFacts.receipt_hash,
            canonicalPaymentFactsJson(paymentFacts),
            paymentFacts.timestamp
          );
      }
    });

    append();
  }

  appendSettlement(settlement: Settlement): void {
    const append = this.db.transaction(() => {
      const receipt = this.getReceiptRowById(settlement.receipt_id);
      if (receipt === null) {
        throw new Error("Settlement receipt does not exist");
      }
      if (receipt.receiptHash !== settlement.receipt_hash) {
        throw new Error("Settlement receipt hash does not match stored receipt hash");
      }

      this.db
        .prepare(
          `INSERT INTO settlements (
            settlement_id,
            receipt_id,
            receipt_hash,
            tx_hash,
            network,
            settlement_json,
            timestamp
          ) VALUES (?, ?, ?, ?, ?, ?, ?)`
        )
        .run(
          settlement.settlement_id,
          settlement.receipt_id,
          settlement.receipt_hash,
          settlement.tx_hash,
          settlement.network,
          canonicalSettlementJson(settlement),
          settlement.timestamp
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

  getPaymentFactsRowByReceiptId(receiptId: string): StoredPaymentFactsRow | null {
    const row = this.db
      .prepare("SELECT facts_id, receipt_id, receipt_hash, facts_json FROM payment_facts WHERE receipt_id = ?")
      .get(receiptId) as StoredPaymentFactsDbRow | undefined;

    if (row === undefined) {
      return null;
    }

    return {
      factsId: row.facts_id,
      receiptId: row.receipt_id,
      receiptHash: row.receipt_hash,
      factsJson: row.facts_json
    };
  }

  listPaymentFactsRows(): readonly StoredPaymentFactsRow[] {
    const rows = this.db
      .prepare("SELECT facts_id, receipt_id, receipt_hash, facts_json FROM payment_facts ORDER BY rowid ASC")
      .all() as StoredPaymentFactsDbRow[];

    return rows.map((row) => ({
      factsId: row.facts_id,
      receiptId: row.receipt_id,
      receiptHash: row.receipt_hash,
      factsJson: row.facts_json
    }));
  }

  getSettlementRowByReceiptId(receiptId: string): StoredSettlementRow | null {
    const row = this.db
      .prepare(
        "SELECT settlement_id, receipt_id, receipt_hash, network, tx_hash, settlement_json FROM settlements WHERE receipt_id = ?"
      )
      .get(receiptId) as StoredSettlementDbRow | undefined;

    if (row === undefined) {
      return null;
    }

    return {
      settlementId: row.settlement_id,
      receiptId: row.receipt_id,
      receiptHash: row.receipt_hash,
      network: row.network,
      txHash: row.tx_hash,
      settlementJson: row.settlement_json
    };
  }

  listSettlementRows(): readonly StoredSettlementRow[] {
    const rows = this.db
      .prepare(
        "SELECT settlement_id, receipt_id, receipt_hash, network, tx_hash, settlement_json FROM settlements ORDER BY rowid ASC"
      )
      .all() as StoredSettlementDbRow[];

    return rows.map((row) => ({
      settlementId: row.settlement_id,
      receiptId: row.receipt_id,
      receiptHash: row.receipt_hash,
      network: row.network,
      txHash: row.tx_hash,
      settlementJson: row.settlement_json
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

      CREATE TABLE IF NOT EXISTS payment_facts (
        facts_id TEXT NOT NULL UNIQUE,
        receipt_id TEXT NOT NULL UNIQUE,
        receipt_hash TEXT NOT NULL,
        facts_json TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        FOREIGN KEY (receipt_id) REFERENCES receipts(receipt_id)
      );

      CREATE TABLE IF NOT EXISTS settlements (
        settlement_id TEXT NOT NULL UNIQUE,
        receipt_id TEXT NOT NULL UNIQUE,
        receipt_hash TEXT NOT NULL,
        tx_hash TEXT NOT NULL,
        network TEXT NOT NULL,
        settlement_json TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        FOREIGN KEY (receipt_id) REFERENCES receipts(receipt_id),
        UNIQUE (network, tx_hash)
      );
    `);
  }
}
