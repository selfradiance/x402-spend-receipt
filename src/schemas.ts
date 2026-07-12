import { z } from "zod";

export const reasonCodes = [
  "ALLOWED",
  "AMOUNT_EXCEEDS_PER_PAYMENT_MAX",
  "SESSION_BUDGET_EXCEEDED",
  "PAY_TO_NOT_ALLOWED",
  "HOST_NOT_ALLOWED",
  "REPEAT_PAYMENT_LOOP",
  "INTENT_INVALID",
  "POLICY_INVALID"
] as const;

export const factsEligibleReasonCodes = [
  "ALLOWED",
  "AMOUNT_EXCEEDS_PER_PAYMENT_MAX",
  "SESSION_BUDGET_EXCEEDED",
  "PAY_TO_NOT_ALLOWED",
  "HOST_NOT_ALLOWED",
  "REPEAT_PAYMENT_LOOP"
] as const;

export const decisionSchema = z.enum(["ALLOW", "DENY"]);
export const reasonCodeSchema = z.enum(reasonCodes);

export const nonNegativeIntegerStringSchema = z.string().regex(/^\d+$/);

export const intentSchema = z
  .object({
    method: z.literal("x402"),
    endpoint_url: z.string().url(),
    pay_to: z.string(),
    asset: z.string(),
    network: z.string(),
    amount_base_units: nonNegativeIntegerStringSchema,
    agent_urn: z.string()
  })
  .strict();

const policyRulesSchema = z
  .object({
    max_per_payment_base_units: nonNegativeIntegerStringSchema,
    session_budget_base_units: nonNegativeIntegerStringSchema,
    pay_to_allowlist: z.array(z.string()),
    endpoint_host_allowlist: z.array(z.string()),
    repeat_payment_rule: z
      .object({
        max_repeats: z.number().int().nonnegative(),
        window_seconds: z.number().int().nonnegative()
      })
      .strict()
  });

const allAllowsPolicySchema = policyRulesSchema
  .extend({
    budget_mode: z.literal("all_allows").optional()
  })
  .strict();

const reservedPolicySchema = policyRulesSchema
  .extend({
    budget_mode: z.literal("reserved"),
    reservation_window_seconds: z.number().int().positive()
  })
  .strict();

export const policySchema = z.union([allAllowsPolicySchema, reservedPolicySchema]);

export const receiptSchema = z
  .object({
    schema_version: z.literal("1.0"),
    receipt_id: z.string().uuid(),
    timestamp: z.string().datetime({ offset: true }),
    agent_urn: z.string(),
    intent_digest: z.string().regex(/^[a-f0-9]{64}$/),
    policy_digest: z.string().regex(/^[a-f0-9]{64}$/),
    decision: decisionSchema,
    reason_code: reasonCodeSchema,
    prev_receipt_hash: z.string().regex(/^[a-f0-9]{64}$/).nullable(),
    key_id: z.string(),
    signature: z.string()
  })
  .strict();

const ed25519SignatureSchema = z.string();
const sha256HexSchema = z.string().regex(/^[a-f0-9]{64}$/);

export const paymentFactsSchema = z
  .object({
    schema_version: z.literal("1.0"),
    facts_id: z.string().uuid(),
    timestamp: z.string().datetime({ offset: true }),
    receipt_id: z.string().uuid(),
    receipt_hash: sha256HexSchema,
    amount_base_units: nonNegativeIntegerStringSchema,
    asset: z.string(),
    network: z.string(),
    pay_to: z.string(),
    key_id: z.string(),
    signature: ed25519SignatureSchema
  })
  .strict();

export const settlementSchema = z
  .object({
    schema_version: z.literal("1.0"),
    settlement_id: z.string().uuid(),
    timestamp: z.string().datetime({ offset: true }),
    receipt_id: z.string().uuid(),
    receipt_hash: sha256HexSchema,
    tx_hash: z.string().regex(/^0x[0-9a-f]{64}$/),
    network: z.string(),
    key_id: z.string(),
    signature: ed25519SignatureSchema
  })
  .strict();

export const aggregateRangeSchema = z.union([
  z
    .object({
      type: z.literal("receipt_id"),
      from_id: z.string().uuid(),
      to_id: z.string().uuid()
    })
    .strict(),
  z
    .object({
      type: z.literal("time"),
      since: z.string().datetime({ offset: true }),
      until: z.string().datetime({ offset: true })
    })
    .strict()
]);

export const aggregateTotalsSchema = z
  .object({
    asset: z.string(),
    network: z.string(),
    settled_base_units: nonNegativeIntegerStringSchema,
    unsettled_allow_base_units: nonNegativeIntegerStringSchema
  })
  .strict();

export const decisionCountsSchema = z
  .object({
    ALLOW: z.number().int().nonnegative(),
    DENY: z.number().int().nonnegative()
  })
  .strict();

export const reasonCodeCountsSchema = z
  .object({
    ALLOWED: z.number().int().nonnegative(),
    AMOUNT_EXCEEDS_PER_PAYMENT_MAX: z.number().int().nonnegative(),
    SESSION_BUDGET_EXCEEDED: z.number().int().nonnegative(),
    PAY_TO_NOT_ALLOWED: z.number().int().nonnegative(),
    HOST_NOT_ALLOWED: z.number().int().nonnegative(),
    REPEAT_PAYMENT_LOOP: z.number().int().nonnegative(),
    INTENT_INVALID: z.number().int().nonnegative(),
    POLICY_INVALID: z.number().int().nonnegative()
  })
  .strict();

export const aggregateSummarySchema = z
  .object({
    schema_version: z.literal("1.0"),
    aggregate_id: z.string().uuid(),
    created_at: z.string().datetime({ offset: true }),
    range: aggregateRangeSchema,
    receipt_count: z.number().int().positive(),
    decision_counts: decisionCountsSchema,
    reason_code_counts: reasonCodeCountsSchema,
    invalid_intent_count: z.number().int().nonnegative(),
    invalid_policy_count: z.number().int().nonnegative(),
    legacy_unproven_count: z.number().int().nonnegative(),
    totals: z.array(aggregateTotalsSchema),
    first_receipt_hash: sha256HexSchema,
    last_receipt_hash: sha256HexSchema,
    merkle_root: sha256HexSchema,
    key_id: z.string(),
    signature: ed25519SignatureSchema
  })
  .strict();

export type Decision = z.infer<typeof decisionSchema>;
export type Intent = z.infer<typeof intentSchema>;
export type Policy = z.infer<typeof policySchema>;
export type ReasonCode = z.infer<typeof reasonCodeSchema>;
export type Receipt = z.infer<typeof receiptSchema>;
export type FactsEligibleReasonCode = (typeof factsEligibleReasonCodes)[number];
export type PaymentFacts = z.infer<typeof paymentFactsSchema>;
export type Settlement = z.infer<typeof settlementSchema>;
export type AggregateRange = z.infer<typeof aggregateRangeSchema>;
export type AggregateTotals = z.infer<typeof aggregateTotalsSchema>;
export type AggregateSummary = z.infer<typeof aggregateSummarySchema>;

export function isFactsEligibleReasonCode(reasonCode: ReasonCode): reasonCode is FactsEligibleReasonCode {
  return (factsEligibleReasonCodes as readonly string[]).includes(reasonCode);
}
