import { randomUUID } from "node:crypto";

import { assertJsonValue, canonicalSha256Hex } from "./canonical.js";
import { createSignedPaymentFacts } from "./facts.js";
import { type Ed25519KeyPair } from "./keys.js";
import { type ReceiptLedgerWriter } from "./ledger.js";
import { evaluatePolicy } from "./policy.js";
import { createSignedReceipt, receiptHash } from "./receipts.js";
import { verifySettlement } from "./settlements.js";
import { intentSchema, isFactsEligibleReasonCode, type Decision, type ReasonCode, type Receipt } from "./schemas.js";

export interface EvaluateAndRecordOptions {
  ledger: ReceiptLedgerWriter;
  keyPair: Ed25519KeyPair;
  now?: Date;
  receiptIdFactory?: () => string;
  factsIdFactory?: () => string;
}

export interface EvaluateAndRecordResult {
  decision: Decision;
  reasonCode: ReasonCode;
  receipt: Receipt | null;
}

export function evaluateAndRecord(
  intentInput: unknown,
  policyInput: unknown,
  options: EvaluateAndRecordOptions
): EvaluateAndRecordResult {
  const now = options.now ?? new Date();
  const evaluation = evaluatePolicy(intentInput, policyInput, {
    history: options.ledger,
    now,
    isSettled: (allowedReceipt) => {
      if (allowedReceipt.receipt_id === undefined || allowedReceipt.receipt_hash === undefined) {
        return false;
      }

      const settlementRow = options.ledger.getSettlementRowByReceiptId(allowedReceipt.receipt_id);
      if (settlementRow === null || settlementRow.receiptHash !== allowedReceipt.receipt_hash) {
        return false;
      }

      try {
        const settlement = JSON.parse(settlementRow.settlementJson);
        return verifySettlement(settlement, options.keyPair.publicKey) && settlement.receipt_hash === allowedReceipt.receipt_hash;
      } catch {
        return false;
      }
    }
  });

  try {
    const parsedIntent = intentSchema.safeParse(intentInput);
    const receipt = createSignedReceipt({
      receiptId: options.receiptIdFactory?.() ?? randomUUID(),
      timestamp: now.toISOString(),
      agentUrn: parsedIntent.success ? parsedIntent.data.agent_urn : extractAgentUrn(intentInput),
      intentDigest: canonicalSha256Hex(assertJsonValue(intentInput)),
      policyDigest: canonicalSha256Hex(assertJsonValue(policyInput)),
      decision: evaluation.decision,
      reasonCode: evaluation.reasonCode,
      prevReceiptHash: options.ledger.getLastReceiptHash(),
      keyPair: options.keyPair
    });

    const paymentFacts =
      parsedIntent.success && isFactsEligibleReasonCode(evaluation.reasonCode)
        ? createSignedPaymentFacts({
            factsId: options.factsIdFactory?.() ?? randomUUID(),
            timestamp: now.toISOString(),
            receiptId: receipt.receipt_id,
            receiptHash: receiptHash(receipt),
            amountBaseUnits: parsedIntent.data.amount_base_units,
            asset: parsedIntent.data.asset,
            network: parsedIntent.data.network,
            payTo: parsedIntent.data.pay_to,
            keyPair: options.keyPair
          })
        : undefined;

    options.ledger.appendReceipt(receipt, {
      endpointUrl: parsedIntent.success ? parsedIntent.data.endpoint_url : null,
      amountBaseUnits: parsedIntent.success ? parsedIntent.data.amount_base_units : null
    }, paymentFacts);

    return {
      decision: receipt.decision,
      reasonCode: receipt.reason_code,
      receipt
    };
  } catch {
    return {
      decision: "DENY",
      reasonCode: evaluation.reasonCode === "ALLOWED" ? "POLICY_INVALID" : evaluation.reasonCode,
      receipt: null
    };
  }
}

function extractAgentUrn(intentInput: unknown): string {
  if (typeof intentInput === "object" && intentInput !== null && "agent_urn" in intentInput) {
    const agentUrn = intentInput.agent_urn;
    if (typeof agentUrn === "string") {
      return agentUrn;
    }
  }

  return "";
}
