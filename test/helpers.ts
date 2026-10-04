import { readFileSync } from 'node:fs';
import { Keypair, LAMPORTS_PER_SOL } from '@solana/web3.js';
import { DEMO } from '../src/demo/identities.js';
import { parsePolicy, type PolicyFile } from '../src/policy/schema.js';
import { MemoryLedger } from '../src/solana/ledger.js';

export function demoPolicy(): PolicyFile {
  return parsePolicy(JSON.parse(readFileSync(new URL('../policies/demo.policy.json', import.meta.url), 'utf8')));
}

export const addr = (k: keyof typeof DEMO) => DEMO[k]().publicKey.toBase58();

/** A memory ledger with a funded custody wallet and the demo USDC mint. */
export async function seededLedger(custody: Keypair = DEMO.custody()) {
  const ledger = new MemoryLedger();
  const auth = DEMO.mintAuthority();
  await ledger.airdrop(custody.publicKey, 2n * BigInt(LAMPORTS_PER_SOL));
  await ledger.createMint(DEMO.usdcMint(), 6, auth);
  await ledger.mintTo(DEMO.usdcMint().publicKey, custody.publicKey, 1_000_000_000n, auth);
  await ledger.createMint(DEMO.mysteryMint(), 6, auth);
  await ledger.mintTo(DEMO.mysteryMint().publicKey, custody.publicKey, 1_000_000_000n, auth);
  return ledger;
}
