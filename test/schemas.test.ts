import { describe, expect, it } from "vitest";

import { intentSchema, policySchema, reasonCodes, receiptSchema } from "../src/index.js";

const validIntent = {
  method: "x402",
  endpoint_url: "https://api.example.com/metered",
  pay_to: "0xabc123",
  asset: "USDC",
  network: "base",
  amount_base_units: "1500000",
  agent_urn: "urn:agent:demo"
};

const validPolicy = {
  max_per_payment_base_units: "2000000",
  session_budget_base_units: "5000000",
  pay_to_allowlist: ["0xabc123"],
  endpoint_host_allowlist: ["api.example.com"],
  repeat_payment_rule: {
    max_repeats: 2,
    window_seconds: 60
  }
};

describe("schemas", () => {
  it("exports the fixed reason code vocabulary", () => {
    expect(reasonCodes).toEqual([
      "ALLOWED",
      "AMOUNT_EXCEEDS_PER_PAYMENT_MAX",
      "SESSION_BUDGET_EXCEEDED",
      "PAY_TO_NOT_ALLOWED",
      "HOST_NOT_ALLOWED",
      "REPEAT_PAYMENT_LOOP",
      "INTENT_INVALID",
      "POLICY_INVALID"
    ]);
  });

  it("validates the x402 intent shape", () => {
    expect(intentSchema.safeParse(validIntent).success).toBe(true);
  });

  it("rejects float, negative, and numeric amounts", () => {
    expect(intentSchema.safeParse({ ...validIntent, amount_base_units: "1.5" }).success).toBe(false);
    expect(intentSchema.safeParse({ ...validIntent, amount_base_units: "-1" }).success).toBe(false);
    expect(intentSchema.safeParse({ ...validIntent, amount_base_units: 1500000 }).success).toBe(false);
  });

  it("rejects unknown intent fields", () => {
    expect(intentSchema.safeParse({ ...validIntent, extra: true }).success).toBe(false);
  });

  it("validates exactly the five policy rules", () => {
    expect(policySchema.safeParse(validPolicy).success).toBe(true);
    expect(policySchema.safeParse({ ...validPolicy, unknown_rule: true }).success).toBe(false);
  });

  it("validates receipt shape", () => {
    const receipt = {
      schema_version: "1.0",
      receipt_id: "00000000-0000-4000-8000-000000000000",
      timestamp: "2026-06-10T22:30:00.000Z",
      agent_urn: "urn:agent:demo",
      intent_digest: "a".repeat(64),
      policy_digest: "b".repeat(64),
      decision: "ALLOW",
      reason_code: "ALLOWED",
      prev_receipt_hash: null,
      key_id: "local-key",
      signature: "signature-placeholder"
    };

    expect(receiptSchema.safeParse(receipt).success).toBe(true);
    expect(receiptSchema.safeParse({ ...receipt, reason_code: "NOT_A_REASON" }).success).toBe(false);
  });
});
