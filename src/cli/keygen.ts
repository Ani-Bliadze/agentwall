import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { Keypair } from '@solana/web3.js';

/** Generate a custody wallet plus admin and agent API keys for a new deployment. */
const path = process.argv[2] ?? 'data/custody-keypair.json';
if (existsSync(path)) {
  console.error(`${path} already exists. Refusing to overwrite a wallet.`);
  process.exit(1);
}
mkdirSync(dirname(path), { recursive: true });
const kp = Keypair.generate();
writeFileSync(path, JSON.stringify(Array.from(kp.secretKey)), { mode: 0o600 });

const key = (prefix: string) => `${prefix}_${randomBytes(18).toString('hex')}`;
console.log(`Custody wallet ${kp.publicKey.toBase58()} written to ${path}

Add these to .env:

AGENTWALL_KEYPAIR=${path}
AGENTWALL_ADMIN_TOKEN=${key('aw_admin')}
AGENTWALL_AGENT_KEYS=research-agent:${key('aw_research')},ops-agent:${key('aw_ops')}

On devnet, fund the wallet with SOL (https://faucet.solana.com) and devnet USDC (https://faucet.circle.com).`);
