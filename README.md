# x402-spend-receipt

`x402-spend-receipt` is a local policy gate and signed audit ledger for x402 payment intents. It evaluates a proposed payment before the caller makes it, then records an Ed25519-signed, hash-chained `ALLOW` or `DENY` receipt.

Version 0.2 also records signed payment facts, locally attested settlement links, and signed spend summaries with portable audit bundles.

## Boundaries

This package does not make payments, hold funds, use wallets, proxy requests, or call a network. A settlement record is an operator's signed local claim that a transaction hash settled a receipt. It does **not** prove that the transaction exists, succeeded, or paid the stated recipient.

All checks, receipts, summaries, and verification run locally and deterministically. Unknown or malformed policy/intent input is denied.

## Install and initialize

```bash
npm install -g x402-spend-receipt
x402-spend-receipt init
```

`init` creates this local state directory (or `$XDG_CONFIG_HOME/x402-spend-receipt` when set):

```text
ed25519.private.key  # mode 600
ed25519.public.key
policy.json
ledger.sqlite
```

## Policy

The generated policy is:

```json
{
  "max_per_payment_base_units": "1000000",
  "session_budget_base_units": "10000000",
  "pay_to_allowlist": ["replace-with-payment-address"],
  "endpoint_host_allowlist": ["api.example.com"],
  "repeat_payment_rule": {
    "max_repeats": 2,
    "window_seconds": 60
  },
  "budget_mode": "all_allows"
}
```

Amounts are non-negative integer strings in base units. With `all_allows` (the default), every prior `ALLOW` counts against `session_budget_base_units`, exactly as in v0.1.1.

`reserved` is available when an operator needs dry runs to stop counting after a fixed window:

```json
{
  "budget_mode": "reserved",
  "reservation_window_seconds": 3600
}
```

In `reserved` mode, an unsettled `ALLOW` counts only while `now < receipt timestamp + reservation_window_seconds`; it stops counting at the boundary. A valid signed settlement always counts, regardless of age. This is bypassable, audit-oriented accounting—not a hard spending limit—because an agent can leave an `ALLOW` unsettled until the window expires.

`reservation_window_seconds` is required only for `reserved`, must be a positive integer, and is rejected with `all_allows`.

## Check and verify receipts

```bash
x402-spend-receipt check intent.json
x402-spend-receipt verify receipt.json --pubkey "$(cat ~/.config/x402-spend-receipt/ed25519.public.key)"
x402-spend-receipt verify-chain
x402-spend-receipt export <receipt_id>
```

`check` exits `0` for `ALLOW` and `1` for `DENY`; both produce a signed receipt. These original commands retain their v0.1.1 output and exit behavior.

## Settlement attestations

```bash
x402-spend-receipt record-settlement <receipt_id> \
  --tx 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --network eip155:8453
```

This command only accepts an unsettled, facts-backed `ALLOW`. It verifies the local chain, receipt, and signed payment facts before writing a settlement record. One receipt may have one settlement; one `(network, tx_hash)` pair may link to one receipt.

The transaction hash format is `0x` plus 64 hexadecimal characters. It is stored lowercase. Networks use CAIP-2 syntax. Payment facts preserve the intent's network string; settlement comparison maps only `base` to `eip155:8453` and `base-sepolia` to `eip155:84532`. A valid CAIP-2 value compares unchanged and case-sensitively.

## Aggregates

Create a signed summary over an inclusive receipt-ID range or a time range (`since` inclusive, `until` exclusive):

```bash
x402-spend-receipt aggregate \
  --from-id <first_receipt_id> --to-id <last_receipt_id> \
  --out summary.json

x402-spend-receipt aggregate \
  --since 2026-06-10T00:00:00.000Z --until 2026-06-11T00:00:00.000Z \
  --out summary.json

x402-spend-receipt verify-aggregate summary.json
```

`--allow-legacy` permits v0.1.1 receipts without payment facts. They remain in receipt/reason counts but add zero to proven monetary totals and increase `legacy_unproven_count`. Without it, such a range is rejected. Existing output files are protected unless `--force` is supplied.

The signed summary schema is:

```text
schema_version, aggregate_id, created_at, range, receipt_count,
decision_counts, reason_code_counts, invalid_intent_count,
invalid_policy_count, legacy_unproven_count, totals,
first_receipt_hash, last_receipt_hash, merkle_root, key_id, signature
```

`totals` is an array of `(asset, network)` groups with separate decimal-string `settled_base_units` and `unsettled_allow_base_units` fields. Different assets or networks are never added together.

## Portable audit bundles

```bash
x402-spend-receipt export-audit \
  --from-id <first_receipt_id> --to-id <last_receipt_id> \
  --out audit-bundle

x402-spend-receipt verify-aggregate \
  --bundle audit-bundle \
  --pubkey ~/.config/x402-spend-receipt/ed25519.public.key
```

`export-audit` creates its summary internally and writes a temporary directory before atomically renaming it into place. The bundle contains:

```text
manifest.json                 # signed inventory and ordered receipt list
summary.json                  # signed aggregate
pubkey.json                   # informational only; never trusted by the verifier
receipts/<sequence>-<id>.json
facts/<sequence>-<id>.json
settlements/<sequence>-<id>.json
```

`manifest.json` signs the ordered `(receipt_id, receipt_hash)` list, each included file's SHA-256, and the SHA-256 of `summary.json`. Third-party verification trusts only the separately supplied `--pubkey`; it verifies signatures, links, cardinality, file inventory, order, Merkle root, counts, and totals.

Third-party verification proves that the supplied bundle matches the signed summary for its selected range. It cannot prove that the signer omitted no records outside that range.

## Merkle rule

The summary root uses RFC 6962 Merkle Tree Hash over receipt hashes in ledger-chain order:

```text
leaf = SHA-256(0x00 || receipt_hash_bytes)
node = SHA-256(0x01 || left || right)
```

For every batch larger than one, the tree splits recursively at the largest power of two smaller than the batch size.

## New-command errors

The four new commands—`record-settlement`, `aggregate`, `export-audit`, and `verify-aggregate`—print failures to stdout as:

```json
{"ok": false, "code": "<CODE>", "message": "..."}
```

They exit `1`; success exits `0`. The code vocabulary is:

```text
INVALID_TX_HASH INVALID_NETWORK CHAIN_INVALID RECEIPT_SIGNATURE_INVALID
FACTS_SIGNATURE_INVALID SETTLEMENT_SIGNATURE_INVALID SETTLEMENT_BINDING_INVALID
SETTLEMENT_ON_DENY RECEIPT_NOT_FOUND NO_PAYMENT_FACTS ALREADY_SETTLED
TX_ALREADY_LINKED SETTLEMENT_NETWORK_MISMATCH SETTLEMENT_NETWORK_UNMAPPED
INVALID_RANGE EMPTY_RANGE FILE_EXISTS LEGACY_RECEIPTS_IN_RANGE
SUMMARY_SIGNATURE_INVALID TOTALS_MISMATCH PUBKEY_REQUIRED
FACTS_CARDINALITY_INVALID SETTLEMENT_CARDINALITY_INVALID
BUNDLE_MISSING_RECORD BUNDLE_EXTRANEOUS_RECORD BUNDLE_DUPLICATE_RECORD
BUNDLE_ORDER_MISMATCH SIGNATURE_KEY_MISMATCH MANIFEST_SIGNATURE_INVALID
```

## Signed record schemas

Payment facts contain `schema_version`, `facts_id`, `timestamp`, `receipt_id`, `receipt_hash`, `amount_base_units`, `asset`, `network`, `pay_to`, `key_id`, and `signature`.

Settlement records contain `schema_version`, `settlement_id`, `timestamp`, `receipt_id`, `receipt_hash`, `tx_hash`, `network`, `key_id`, and `signature`.

Audit manifests contain `schema_version`, `bundle_id`, `created_at`, ordered receipt IDs/hashes, file inventory, `summary_sha256`, `key_id`, and `signature`.

All three use strict schemas, Ed25519 signatures, canonical JSON, and distinct signing prefixes. v0.1.1 receipt JSON is unchanged.

## Development

```bash
npm test
npm run lint
npm run typecheck
npm run build
```

License: MIT.
