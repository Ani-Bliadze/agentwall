import { describe, expect, it } from 'vitest';
import { Keypair, PublicKey, SystemProgram, Transaction, TransactionInstruction } from '@solana/web3.js';
import { createApproveInstruction, createCloseAccountInstruction, getAssociatedTokenAddressSync } from '@solana/spl-token';
import { DEMO } from '../src/demo/identities.js';
import { buildTransfer } from '../src/solana/builder.js';
import { inspectTransaction } from '../src/solana/inspector.js';
import { seededLedger } from './helpers.js';

const custody = DEMO.custody();
const usdc = DEMO.usdcMint().publicKey;

async function finalize(ledger: Awaited<ReturnType<typeof seededLedger>>, ...ixs: TransactionInstruction[]) {
  const tx = new Transaction().add(...ixs);
  tx.feePayer = custody.publicKey;
  tx.recentBlockhash = await ledger.latestBlockhash();
  return tx;
}

describe('transaction inspector', () => {
  it('decodes a SOL transfer', async () => {
    const ledger = await seededLedger();
    const to = Keypair.generate().publicKey;
    const tx = await finalize(ledger, SystemProgram.transfer({ fromPubkey: custody.publicKey, toPubkey: to, lamports: 1234 }));
    const r = await inspectTransaction(tx, (a) => ledger.getTokenAccount(a));
    expect(r.transfers).toHaveLength(1);
    expect(r.transfers[0]).toMatchObject({ kind: 'sol', amount: 1234n, destinationOwner: to.toBase58() });
    expect(r.signers).toEqual([custody.publicKey.toBase58()]);
  });

  it('decodes a USDC transfer to a new token account and a memo', async () => {
    const ledger = await seededLedger();
    const to = DEMO.acmeCloud().publicKey;
    const tx = await buildTransfer(ledger, { from: custody.publicKey, to, amount: 5_000_000n, mint: usdc, decimals: 6, memo: 'INV-1' });
    // serialize/deserialize to make sure we inspect wire bytes, not JS objects
    const wire = tx.serialize({ requireAllSignatures: false, verifySignatures: false }).toString('base64');
    const r = await inspectTransaction(wire, (a) => ledger.getTokenAccount(a));
    expect(r.instructions.map((i) => `${i.program}.${i.name}`)).toEqual([
      'associated-token.createAssociatedTokenAccountIdempotent',
      'spl-token.transferChecked',
      'memo.memo',
    ]);
    expect(r.transfers[0]).toMatchObject({ kind: 'spl', amount: 5_000_000n, mint: usdc.toBase58(), destinationOwner: to.toBase58() });
    expect(r.memos).toEqual(['INV-1']);
  });

  it('flags delegate approvals and account closures as dangerous', async () => {
    const ledger = await seededLedger();
    const ata = getAssociatedTokenAddressSync(usdc, custody.publicKey);
    const attacker = Keypair.generate().publicKey;
    const tx = await finalize(
      ledger,
      createApproveInstruction(ata, attacker, custody.publicKey, 1n),
      createCloseAccountInstruction(ata, attacker, custody.publicKey),
    );
    const r = await inspectTransaction(tx, (a) => ledger.getTokenAccount(a));
    expect(r.instructions.map((i) => [i.name, i.risk])).toEqual([
      ['approve', 'dangerous'],
      ['closeAccount', 'dangerous'],
    ]);
  });

  it('marks programs it cannot decode', async () => {
    const ledger = await seededLedger();
    const ix = new TransactionInstruction({ programId: new PublicKey('JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4'), keys: [{ pubkey: custody.publicKey, isSigner: true, isWritable: true }], data: Buffer.from([1, 2, 3]) });
    const r = await inspectTransaction(await finalize(ledger, ix), (a) => ledger.getTokenAccount(a));
    expect(r.instructions[0].risk).toBe('unknown_program');
  });
});
