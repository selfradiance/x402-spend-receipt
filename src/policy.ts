import { intentSchema, policySchema, type Intent, type Policy, type ReasonCode } from "./schemas.js";

export type PolicyDecision = "ALLOW" | "DENY";

export interface AllowedReceiptHistoryEntry {
  endpoint_url: string;
  amount_base_units: string;
  timestamp: string;
}

export interface ReceiptHistoryReader {
  listAllowedReceipts(): readonly AllowedReceiptHistoryEntry[];
}

export interface PolicyEvaluation {
  decision: PolicyDecision;
  reasonCode: ReasonCode;
}

export interface PolicyEvaluationOptions {
  history?: ReceiptHistoryReader;
  now?: Date;
}

const emptyHistory: ReceiptHistoryReader = {
  listAllowedReceipts: () => []
};

export function evaluatePolicy(
  intentInput: unknown,
  policyInput: unknown,
  options: PolicyEvaluationOptions = {}
): PolicyEvaluation {
  const parsedIntent = intentSchema.safeParse(intentInput);
  if (!parsedIntent.success) {
    return deny("INTENT_INVALID");
  }

  const parsedPolicy = policySchema.safeParse(policyInput);
  if (!parsedPolicy.success) {
    return deny("POLICY_INVALID");
  }

  const intent = parsedIntent.data;
  const policy = parsedPolicy.data;

  const amount = BigInt(intent.amount_base_units);
  const maxPerPayment = BigInt(policy.max_per_payment_base_units);
  if (amount > maxPerPayment) {
    return deny("AMOUNT_EXCEEDS_PER_PAYMENT_MAX");
  }

  const history = options.history ?? emptyHistory;
  const allowedReceipts = history.listAllowedReceipts();
  const priorAllowedSpend = sumAllowedSpend(allowedReceipts);
  const sessionBudget = BigInt(policy.session_budget_base_units);
  if (priorAllowedSpend + amount > sessionBudget) {
    return deny("SESSION_BUDGET_EXCEEDED");
  }

  if (!policy.pay_to_allowlist.includes(intent.pay_to)) {
    return deny("PAY_TO_NOT_ALLOWED");
  }

  const endpointHost = getEndpointHostname(intent.endpoint_url);
  if (endpointHost === null || !policy.endpoint_host_allowlist.includes(endpointHost)) {
    return deny("HOST_NOT_ALLOWED");
  }

  if (isRepeatPaymentLoop(intent, policy, allowedReceipts, options.now ?? new Date())) {
    return deny("REPEAT_PAYMENT_LOOP");
  }

  return {
    decision: "ALLOW",
    reasonCode: "ALLOWED"
  };
}

function deny(reasonCode: Exclude<ReasonCode, "ALLOWED">): PolicyEvaluation {
  return {
    decision: "DENY",
    reasonCode
  };
}

function sumAllowedSpend(allowedReceipts: readonly AllowedReceiptHistoryEntry[]): bigint {
  return allowedReceipts.reduce((total, receipt) => total + BigInt(receipt.amount_base_units), 0n);
}

function getEndpointHostname(endpointUrl: string): string | null {
  try {
    return new URL(endpointUrl).hostname;
  } catch {
    return null;
  }
}

function isRepeatPaymentLoop(
  intent: Intent,
  policy: Policy,
  allowedReceipts: readonly AllowedReceiptHistoryEntry[],
  now: Date
): boolean {
  const windowStartMs = now.getTime() - policy.repeat_payment_rule.window_seconds * 1000;
  const repeatsInWindow = allowedReceipts.filter((receipt) => {
    const receiptTime = Date.parse(receipt.timestamp);

    return (
      Number.isFinite(receiptTime) &&
      receiptTime >= windowStartMs &&
      receiptTime <= now.getTime() &&
      receipt.endpoint_url === intent.endpoint_url &&
      receipt.amount_base_units === intent.amount_base_units
    );
  }).length;

  return repeatsInWindow > policy.repeat_payment_rule.max_repeats;
}
