# x402-spend-receipt

Local policy checks and signed receipts for x402 payment intents.

`x402-spend-receipt` is an artifact layer. It evaluates an AI agent's proposed x402 payment intent against a local JSON policy before payment, then writes an Ed25519-signed, hash-chained receipt for the decision.

It records both `ALLOW` and `DENY` decisions.

## What This Does Not Do

This package does not make payments. It does not touch funds, wallets, wallet private keys, payment credentials, or hosted services. It does not proxy traffic. It does not call the network.

Everything runs locally and deterministically. Malformed or unknown inputs default to deny.

## Install

```bash
npm install -g x402-spend-receipt
```

Or run it through `npx`:

```bash
npx x402-spend-receipt --help
```

Requires Node.js 20 or newer.

## Initialize Local State

```bash
npx x402-spend-receipt init
```

This creates local files under:

```text
~/.config/x402-spend-receipt/
```

It writes:

- `ed25519.private.key`
- `ed25519.public.key`
- `policy.json`
- `ledger.sqlite`

The private key file is created with mode `600`.

## Policy File

The generated `policy.json` contains exactly the five v0.1 policy rules:

```json
{
  "max_per_payment_base_units": "1000000",
  "session_budget_base_units": "10000000",
  "pay_to_allowlist": ["replace-with-payment-address"],
  "endpoint_host_allowlist": ["api.example.com"],
  "repeat_payment_rule": {
    "max_repeats": 2,
    "window_seconds": 60
  }
}
```

Amounts are integer strings in base units. For USDC, `1000000` means 1.000000 USDC.

## Intent File

An intent JSON file must look like this:

```json
{
  "method": "x402",
  "endpoint_url": "https://api.example.com/metered",
  "pay_to": "replace-with-payment-address",
  "asset": "USDC",
  "network": "base",
  "amount_base_units": "1000000",
  "agent_urn": "urn:agent:demo"
}
```

`amount_base_units` must be a non-negative integer string. Floats, negative values, numbers, extra fields, and malformed JSON are denied.

## Check an Intent

```bash
npx x402-spend-receipt check intent.json
```

Exit codes:

- `0` means `ALLOW`
- `1` means `DENY`

The command prints JSON with the decision, reason code, and signed receipt.

## Verify One Receipt

```bash
npx x402-spend-receipt verify receipt.json --pubkey "$(cat ~/.config/x402-spend-receipt/ed25519.public.key)"
```

This verifies the receipt signature offline.

## Verify the Ledger Chain

```bash
npx x402-spend-receipt verify-chain
```

This walks the local SQLite ledger and fails if any receipt hash, previous hash, or signature is broken.

## Export a Receipt

```bash
npx x402-spend-receipt export <receipt_id>
```

This prints one portable receipt JSON object including the public key.

## Reason Codes

The fixed reason-code vocabulary is:

```text
ALLOWED
AMOUNT_EXCEEDS_PER_PAYMENT_MAX
SESSION_BUDGET_EXCEEDED
PAY_TO_NOT_ALLOWED
HOST_NOT_ALLOWED
REPEAT_PAYMENT_LOOP
INTENT_INVALID
POLICY_INVALID
```

Checks run in this order, and the first failure wins:

```text
intent valid
policy valid
per-payment max
session budget
pay_to allowlist
host allowlist
repeat loop
```

## Wrapper Example

This example checks an intent before running another command. If the policy check denies the intent, the script aborts before `npx x402-proxy <url>` is run.

```bash
#!/usr/bin/env bash
set -euo pipefail

url="https://api.example.com/metered"
intent_file="$(mktemp)"

cat > "$intent_file" <<JSON
{
  "method": "x402",
  "endpoint_url": "$url",
  "pay_to": "replace-with-payment-address",
  "asset": "USDC",
  "network": "base",
  "amount_base_units": "1000000",
  "agent_urn": "urn:agent:demo"
}
JSON

if ! npx x402-spend-receipt check "$intent_file" > receipt.json; then
  echo "x402 payment intent denied; aborting"
  exit 1
fi

npx x402-proxy "$url"
```

`x402-spend-receipt` does not run, proxy, or inspect `x402-proxy`. The script simply uses the local receipt check as a gate before running your next command.

## Library

The package exports the core building blocks used by the CLI:

- `evaluatePolicy`
- `evaluateAndRecord`
- `verifyReceipt`
- `verifyChain`
- `generateEd25519KeyPair`
- `SqliteReceiptLedger`

## Development

```bash
npm test
npm run lint
npm run build
```

License: MIT.
