import { describe, expect, it } from "vitest";

import { evaluatePolicy, policySchema, type AllowedReceiptHistoryEntry, type ReceiptHistoryReader } from "../src/index.js";

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
  session_budget_base_units: "250",
  pay_to_allowlist: ["0xabc123"],
  endpoint_host_allowlist: ["api.example.com"],
  repeat_payment_rule: {
    max_repeats: 1,
    window_seconds: 60
  }
};

function history(entries: readonly AllowedReceiptHistoryEntry[]): ReceiptHistoryReader {
  return {
    listAllowedReceipts: () => entries
  };
}

function allowedEntry(
  overrides: Partial<AllowedReceiptHistoryEntry> = {}
): AllowedReceiptHistoryEntry {
  return {
    endpoint_url: "https://api.example.com/metered",
    amount_base_units: "100",
    timestamp: "2026-06-10T21:59:30.000Z",
    ...overrides
  };
}

describe("policy evaluation", () => {
  it("returns ALLOWED when every check passes", () => {
    expect(evaluatePolicy(validIntent, validPolicy, { now })).toEqual({
      decision: "ALLOW",
      reasonCode: "ALLOWED"
    });
  });

  it("returns INTENT_INVALID before checking policy validity", () => {
    const malformedIntent = {
      ...validIntent,
      amount_base_units: "1.5"
    };
    const malformedPolicy = {
      ...validPolicy,
      max_per_payment_base_units: "-1"
    };

    expect(() => evaluatePolicy(malformedIntent, malformedPolicy, { now })).not.toThrow();
    expect(evaluatePolicy(malformedIntent, malformedPolicy, { now })).toEqual({
      decision: "DENY",
      reasonCode: "INTENT_INVALID"
    });
  });

  it("returns POLICY_INVALID after intent validity passes", () => {
    const malformedPolicy = {
      ...validPolicy,
      repeat_payment_rule: {
        max_repeats: -1,
        window_seconds: 60
      }
    };

    expect(() => evaluatePolicy(validIntent, malformedPolicy, { now })).not.toThrow();
    expect(evaluatePolicy(validIntent, malformedPolicy, { now })).toEqual({
      decision: "DENY",
      reasonCode: "POLICY_INVALID"
    });
  });

  it("returns AMOUNT_EXCEEDS_PER_PAYMENT_MAX before later policy checks", () => {
    const overMaxIntent = {
      ...validIntent,
      pay_to: "not-allowed",
      amount_base_units: "101"
    };

    expect(evaluatePolicy(overMaxIntent, validPolicy, { now })).toEqual({
      decision: "DENY",
      reasonCode: "AMOUNT_EXCEEDS_PER_PAYMENT_MAX"
    });
  });

  it("allows amount exactly equal to max_per_payment and denies one base unit over", () => {
    expect(
      evaluatePolicy({ ...validIntent, amount_base_units: "100" }, validPolicy, {
        now
      }).reasonCode
    ).toBe("ALLOWED");
    expect(
      evaluatePolicy({ ...validIntent, amount_base_units: "101" }, validPolicy, {
        now
      }).reasonCode
    ).toBe("AMOUNT_EXCEEDS_PER_PAYMENT_MAX");
  });

  it("returns SESSION_BUDGET_EXCEEDED before allowlist checks", () => {
    const notAllowedPayToIntent = {
      ...validIntent,
      pay_to: "not-allowed"
    };
    const priorAllowed = history([allowedEntry({ amount_base_units: "151" })]);

    expect(evaluatePolicy(notAllowedPayToIntent, validPolicy, { history: priorAllowed, now })).toEqual({
      decision: "DENY",
      reasonCode: "SESSION_BUDGET_EXCEEDED"
    });
  });

  it("allows session budget exactly equal to the limit and denies one base unit over", () => {
    expect(
      evaluatePolicy(validIntent, validPolicy, {
        history: history([allowedEntry({ amount_base_units: "150" })]),
        now
      }).reasonCode
    ).toBe("ALLOWED");
    expect(
      evaluatePolicy(validIntent, validPolicy, {
        history: history([allowedEntry({ amount_base_units: "151" })]),
        now
      }).reasonCode
    ).toBe("SESSION_BUDGET_EXCEEDED");
  });

  it("returns PAY_TO_NOT_ALLOWED before host checks", () => {
    const disallowedIntent = {
      ...validIntent,
      endpoint_url: "https://blocked.example.com/metered",
      pay_to: "not-allowed"
    };

    expect(evaluatePolicy(disallowedIntent, validPolicy, { now })).toEqual({
      decision: "DENY",
      reasonCode: "PAY_TO_NOT_ALLOWED"
    });
  });

  it("returns HOST_NOT_ALLOWED before repeat-loop checks", () => {
    const disallowedHostIntent = {
      ...validIntent,
      endpoint_url: "https://blocked.example.com/metered"
    };
    const roomyBudgetPolicy = {
      ...validPolicy,
      session_budget_base_units: "1000"
    };
    const repeatingHistory = history([
      allowedEntry({ endpoint_url: "https://blocked.example.com/metered" }),
      allowedEntry({ endpoint_url: "https://blocked.example.com/metered" })
    ]);

    expect(evaluatePolicy(disallowedHostIntent, roomyBudgetPolicy, { history: repeatingHistory, now })).toEqual({
      decision: "DENY",
      reasonCode: "HOST_NOT_ALLOWED"
    });
  });

  it("returns REPEAT_PAYMENT_LOOP for too many matching prior allows inside the window", () => {
    const roomyBudgetPolicy = {
      ...validPolicy,
      session_budget_base_units: "1000"
    };
    const repeatingHistory = history([allowedEntry(), allowedEntry()]);

    expect(evaluatePolicy(validIntent, roomyBudgetPolicy, { history: repeatingHistory, now })).toEqual({
      decision: "DENY",
      reasonCode: "REPEAT_PAYMENT_LOOP"
    });
  });

  it("keeps omitted budget mode compatible and validates the two supported modes", () => {
    expect(policySchema.safeParse(validPolicy).success).toBe(true);
    expect(policySchema.safeParse({ ...validPolicy, budget_mode: "all_allows" }).success).toBe(true);
    expect(
      policySchema.safeParse({ ...validPolicy, budget_mode: "reserved", reservation_window_seconds: 3600 }).success
    ).toBe(true);
    expect(policySchema.safeParse({ ...validPolicy, budget_mode: "reserved" }).success).toBe(false);
    expect(
      policySchema.safeParse({ ...validPolicy, budget_mode: "reserved", reservation_window_seconds: 0 }).success
    ).toBe(false);
    expect(
      policySchema.safeParse({ ...validPolicy, budget_mode: "reserved", reservation_window_seconds: -1 }).success
    ).toBe(false);
    expect(
      policySchema.safeParse({ ...validPolicy, budget_mode: "reserved", reservation_window_seconds: 1.5 }).success
    ).toBe(false);
    expect(policySchema.safeParse({ ...validPolicy, budget_mode: "unknown" }).success).toBe(false);
    expect(
      policySchema.safeParse({ ...validPolicy, budget_mode: "all_allows", reservation_window_seconds: 60 }).success
    ).toBe(false);
    expect(policySchema.safeParse({ ...validPolicy, extra_rule: true }).success).toBe(false);
  });

  it("counts reserved ALLOWs strictly before expiry and verified settlements at every age", () => {
    const receiptTime = new Date("2026-06-10T20:00:00.000Z");
    const reservedPolicy = {
      ...validPolicy,
      session_budget_base_units: "100",
      budget_mode: "reserved" as const,
      reservation_window_seconds: 3600
    };
    const priorAllowed = history([
      allowedEntry({
        receipt_id: "00000000-0000-4000-8000-000000000020",
        receipt_hash: "a".repeat(64),
        timestamp: receiptTime.toISOString()
      })
    ]);

    expect(
      evaluatePolicy(validIntent, reservedPolicy, {
        history: priorAllowed,
        now: new Date("2026-06-10T20:59:59.000Z")
      }).reasonCode
    ).toBe("SESSION_BUDGET_EXCEEDED");
    expect(
      evaluatePolicy(validIntent, reservedPolicy, {
        history: priorAllowed,
        now: new Date("2026-06-10T21:00:00.000Z")
      }).reasonCode
    ).toBe("ALLOWED");
    expect(
      evaluatePolicy(validIntent, reservedPolicy, {
        history: priorAllowed,
        now: new Date("2026-06-10T21:00:01.000Z"),
        isSettled: () => true
      }).reasonCode
    ).toBe("SESSION_BUDGET_EXCEEDED");
  });
});
