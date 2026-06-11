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

export const policySchema = z
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
  })
  .strict();

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

export type Decision = z.infer<typeof decisionSchema>;
export type Intent = z.infer<typeof intentSchema>;
export type Policy = z.infer<typeof policySchema>;
export type ReasonCode = z.infer<typeof reasonCodeSchema>;
export type Receipt = z.infer<typeof receiptSchema>;
