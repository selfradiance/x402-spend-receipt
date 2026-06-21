---
name: x402-spend-receipt
description: Local deterministic spend-policy evaluation and Ed25519-signed hash-chained allow/deny receipts for x402 and agent payments.
---

# x402-spend-receipt

## What this is

Use `x402-spend-receipt` to evaluate a local x402 spend intent against a JSON policy and emit an Ed25519-signed allow/deny receipt. Product behavior is local and deterministic, with no network calls. The CLI can also verify individual receipts and verify the local receipt hash chain.

## Install

```bash
npm install -g x402-spend-receipt
```

Or run without installing:

```bash
npx x402-spend-receipt [command]
```

## Commands

- `x402-spend-receipt init`
  - Required arguments: none
  - Help: `-h`, `--help`
- `x402-spend-receipt check <intent.json>`
  - Required arguments: `<intent.json>`
  - Help: `-h`, `--help`
- `x402-spend-receipt verify <receipt.json> --pubkey <key>`
  - Required arguments: `<receipt.json>`, `--pubkey <key>`
  - Help: `-h`, `--help`
- `x402-spend-receipt verify-chain`
  - Required arguments: none
  - Help: `-h`, `--help`
- `x402-spend-receipt export <receipt_id>`
  - Required arguments: `<receipt_id>`
  - Help: `-h`, `--help`
- `x402-spend-receipt help [command]`
  - Required arguments: none
  - Optional arguments: `[command]`
  - Help: `-h`, `--help`

## Worked example

```bash
x402-spend-receipt init
x402-spend-receipt check intent.json > receipt.json
x402-spend-receipt verify receipt.json --pubkey "$(cat ~/.config/x402-spend-receipt/ed25519.public.key)"
```

## Scope and non-goals

This tool is deterministic and local only, with no network calls in product behavior. It is not a payment processor, not custody, and not a runtime enforcer.
