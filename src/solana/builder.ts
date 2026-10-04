import { PublicKey, SystemProgram, Transaction, TransactionInstruction } from '@solana/web3.js';
import {
  createAssociatedTokenAccountIdempotentInstruction,
  createTransferCheckedInstruction,
  getAssociatedTokenAddressSync,
} from '@solana/spl-token';
import type { Ledger } from './ledger.js';
import { MEMO_PROGRAM_ID } from './programs.js';

export interface TransferSpec {
  from: PublicKey;
  to: PublicKey;
  amount: bigint;
  /** null for native SOL. */
  mint: PublicKey | null;
  decimals: number;
  memo?: string;
  /** Defaults to `from`. x402 facilitators pay fees on behalf of the payer. */
  feePayer?: PublicKey;
}

export function memoInstruction(memo: string, signer: PublicKey): TransactionInstruction {
  return new TransactionInstruction({
    programId: MEMO_PROGRAM_ID,
    keys: [{ pubkey: signer, isSigner: true, isWritable: false }],
    data: Buffer.from(memo, 'utf8'),
  });
}

/** Build an unsigned SOL or SPL token transfer, creating the recipient's token account if needed. */
export async function buildTransfer(ledger: Ledger, spec: TransferSpec): Promise<Transaction> {
  const tx = new Transaction();
  if (spec.mint === null) {
    tx.add(SystemProgram.transfer({ fromPubkey: spec.from, toPubkey: spec.to, lamports: spec.amount }));
  } else {
    const source = getAssociatedTokenAddressSync(spec.mint, spec.from, true);
    const destination = getAssociatedTokenAddressSync(spec.mint, spec.to, true);
    if (!(await ledger.getTokenAccount(destination.toBase58()))) {
      tx.add(createAssociatedTokenAccountIdempotentInstruction(spec.from, destination, spec.to, spec.mint));
    }
    tx.add(createTransferCheckedInstruction(source, spec.mint, destination, spec.from, spec.amount, spec.decimals));
  }
  if (spec.memo) tx.add(memoInstruction(spec.memo, spec.from));
  tx.feePayer = spec.feePayer ?? spec.from;
  tx.recentBlockhash = await ledger.latestBlockhash();
  return tx;
}
