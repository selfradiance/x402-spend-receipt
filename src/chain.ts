import { receiptHash, verifyReceipt } from "./receipts.js";
import { receiptSchema } from "./schemas.js";
import { type ReceiptLedgerReader } from "./ledger.js";

export interface ChainVerificationResult {
  valid: boolean;
  error?: string;
  sequence?: number;
  receiptId?: string;
}

export function verifyChain(ledger: ReceiptLedgerReader, publicKey: string): ChainVerificationResult {
  let previousHash: string | null = null;

  for (const row of ledger.listReceiptRows()) {
    let parsedJson: unknown;
    try {
      parsedJson = JSON.parse(row.receiptJson);
    } catch {
      return fail(row.sequence, "Receipt JSON is not parseable");
    }

    const parsedReceipt = receiptSchema.safeParse(parsedJson);
    if (!parsedReceipt.success) {
      return fail(row.sequence, "Receipt does not match schema");
    }

    const receipt = parsedReceipt.data;
    if (receipt.prev_receipt_hash !== previousHash) {
      return fail(row.sequence, "Receipt previous hash does not match prior receipt hash", receipt.receipt_id);
    }

    const actualHash = receiptHash(receipt);
    if (actualHash !== row.receiptHash) {
      return fail(row.sequence, "Stored receipt hash does not match receipt bytes", receipt.receipt_id);
    }

    if (!verifyReceipt(receipt, publicKey)) {
      return fail(row.sequence, "Receipt signature verification failed", receipt.receipt_id);
    }

    previousHash = actualHash;
  }

  return { valid: true };
}

function fail(sequence: number, error: string, receiptId?: string): ChainVerificationResult {
  return {
    valid: false,
    error,
    sequence,
    ...(receiptId === undefined ? {} : { receiptId })
  };
}
