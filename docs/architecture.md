# AgentWall architecture

## Trust model

| Party | Trusted with | Not trusted with |
|-------|--------------|------------------|
| AI agent (and the LLM driving it) | Asking for payments, explaining why | The private key, deciding what is allowed |
| AgentWall | The custody key, enforcing policy | Anything the policy does not allow |
| Operator (human) | Policies, approvals, the kill switch | |
| x402 merchant / facilitator | Settling a payment AgentWall already signed | Changing the amount or the payee |

The agent is treated as potentially compromised at all times. Prompt injection, a malicious tool, or a bug in the agent loop can make it ask for anything. AgentWall only signs what the policy allows, and it decides by decoding the transaction it is about to sign, never by reading the agent's description of it.

## Request pipeline

```
agent request
   │
   ├─ /v1/transfers ──── build transaction (System or SPL transfer, ATA creation, memo)
   ├─ /v1/x402/pay ───── build payment for the quote (fee payer = facilitator if provided)
   └─ /v1/transactions ─ deserialize the agent's unsigned transaction
   │
   ▼
inspectTransaction()      src/solana/inspector.ts
   decode every instruction: program, name, risk (safe / dangerous / unsupported / unknown_program)
   extract SOL and token transfers, resolve token account owners (same-tx ATA creation or ledger lookup)
   collect memos, compute budget settings, required signers
   │
   ▼
evaluate()                src/policy/engine.ts
   price transfers in USD, scan payloads (DLP), run the rules in order
   any deny → deny; else any require_approval → require_approval; else allow
   │
   ├─ allow ─────────────► sign with the custody key
   │                         transfers / raw: submit to the ledger, record the signature
   │                         x402: partially sign, return the X-PAYMENT header for the facilitator
   ├─ require_approval ──► hold in memory with an expiry; the console shows it
   │                         approve → re-evaluate with fresh limits → sign
   │                         reject / expire → done
   └─ deny ──────────────► return the reasons
   │
   ▼
AuditLog.append()         src/audit/log.ts (every step above)
```

The blockhash is refreshed right before signing, because human approvals can take longer than a blockhash lives. This is safe because AgentWall is the only party that has signed at that point.

## Policy rules

Rules are plain functions over the inspected transaction, so adding one is a few lines in `engine.ts`. Each produces a `CheckResult { rule, outcome, message }`. Messages are written to be shown to an LLM as is.

Order matters only for readability of the reasons. Apart from the agent check (an unknown or frozen agent stops evaluation right away), all rules run and every failure is reported.

## x402

AgentWall follows x402 v1 with the `exact` scheme on Solana:

- The 402 body lists `accepts[]` with `maxAmountRequired`, `payTo`, `asset` (mint), `network`, `resource` and `extra.feePayer`.
- AgentWall builds a `transferChecked` from its wallet to the payee's associated token account (creating it if needed), with the facilitator as fee payer, and partially signs.
- The facilitator verifies the transfer matches the quote, adds its fee-payer signature and submits.

On top of the protocol, AgentWall adds: merchant allowlists by URL prefix, a price cap per merchant and per agent, pinning the merchant's `payTo` wallet, checking that the quote's `resource` belongs to the merchant, and DLP over the request the agent is about to send (URL, headers, body).

## Data-loss prevention

`src/dlp/scanner.ts` runs on memos and outbound request data:

| Detector | Method |
|----------|--------|
| Solana private key | base58 strings that decode to 64 bytes; 64-number JSON arrays (CLI keypair files) |
| Seed phrase | 12+ consecutive words from the BIP-39 English list |
| EVM private key | 64 hex characters next to words like "private key" or "secret" |
| API keys | Anthropic, OpenAI, AWS, GitHub, Slack, Google, Stripe, keys in RPC URLs, bearer tokens |
| JWT, passwords | Pattern based |
| Card numbers | Issuer prefix plus Luhn check |
| IBAN | Mod-97 check |
| Email, phone | Pattern based, low severity |

Each agent chooses which types block, which go to a human, and the rest are recorded as warnings. Findings are masked; the raw secret is never stored in the audit log.

## Ledgers

All ledgers implement the same interface (`src/solana/ledger.ts`). The memory ledger is deliberately strict: it verifies ed25519 signatures with Node's crypto, rejects expired blockhashes and replays, charges fees and rent, and applies instructions atomically. The LiteSVM ledger runs the same wire bytes through the real Solana runtime, which keeps the memory ledger honest.

## What would change for production

1. **Key custody**: move the key to a KMS/HSM, or replace it with an on-chain smart wallet where AgentWall holds a limited delegate authority and hard limits are enforced by a program.
2. **State**: requests and approvals in a database; the audit log shipped to append-only storage and anchored on a schedule.
3. **Prices**: oracle prices for non-stable assets.
4. **Coverage**: decoders for more programs (Jupiter, Token-2022 extensions) and support for address lookup tables via RPC resolution.
