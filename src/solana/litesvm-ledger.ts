import bs58 from 'bs58';
import { Keypair, PublicKey, SystemProgram, Transaction, VersionedTransaction } from '@solana/web3.js';
import {
  AccountLayout,
  MINT_SIZE,
  TOKEN_PROGRAM_ID,
  createAssociatedTokenAccountIdempotentInstruction,
  createInitializeMint2Instruction,
  createMintToInstruction,
  getAssociatedTokenAddressSync,
} from '@solana/spl-token';
import type { TokenAccountInfo } from './inspector.js';
import { LedgerError, type DevLedger } from './ledger.js';

/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * Runs transactions through the real Solana runtime (SVM) in-process using
 * LiteSVM: same programs and checks as a validator, no network needed.
 * Transactions cross over as wire bytes, so what runs here is byte-for-byte
 * what AgentWall signed. LiteSVM ships native binaries for Linux and macOS only.
 */
export class LiteSvmLedger implements DevLedger {
  readonly kind = 'litesvm' as const;

  private constructor(
    private svm: any,
    private FailedMeta: any,
    private decodeTx: (bytes: Uint8Array) => unknown,
  ) {}

  static async create(): Promise<LiteSvmLedger> {
    try {
      const mod: any = await import('litesvm');
      const kit: any = await import('@solana/kit');
      const decoder = kit.getTransactionDecoder();
      return new LiteSvmLedger(new mod.LiteSVM(), mod.FailedTransactionMetadata, (b) => decoder.decode(b));
    } catch (e) {
      throw new LedgerError(
        `LiteSVM is not available on this platform (${process.platform}/${process.arch}). Use AGENTWALL_LEDGER=memory instead. ${(e as Error).message}`,
      );
    }
  }

  private account(address: PublicKey | string): { data: Uint8Array } | null {
    const acc = this.svm.getAccount(typeof address === 'string' ? address : address.toBase58());
    return acc && acc.exists ? acc : null;
  }

  async latestBlockhash() {
    return this.svm.latestBlockhash() as string;
  }

  async getSolBalance(owner: PublicKey) {
    return (this.svm.getBalance(owner.toBase58()) as bigint | null) ?? 0n;
  }

  async getTokenBalance(owner: PublicKey, mint: PublicKey, tokenProgram = TOKEN_PROGRAM_ID) {
    const acc = this.account(getAssociatedTokenAddressSync(mint, owner, true, tokenProgram));
    if (!acc) return 0n;
    return AccountLayout.decode(Buffer.from(acc.data).subarray(0, AccountLayout.span)).amount;
  }

  async getTokenAccount(address: string): Promise<TokenAccountInfo | null> {
    const acc = this.account(address);
    if (!acc || acc.data.length < AccountLayout.span) return null;
    const decoded = AccountLayout.decode(Buffer.from(acc.data).subarray(0, AccountLayout.span));
    return { mint: decoded.mint.toBase58(), owner: decoded.owner.toBase58() };
  }

  async sendTransaction(tx: Transaction | VersionedTransaction): Promise<string> {
    const res = this.svm.sendTransaction(this.decodeTx(tx.serialize()));
    if (res instanceof this.FailedMeta) {
      const logs = res.meta().logs().slice(-6).join('\n');
      throw new LedgerError(`Transaction failed: ${res.toString()}\n${logs}`);
    }
    this.svm.expireBlockhash();
    return bs58.encode(res.signature());
  }

  async airdrop(owner: PublicKey, lamports: bigint) {
    const res = this.svm.airdrop(owner.toBase58(), lamports);
    if (!res || res instanceof this.FailedMeta) throw new LedgerError('Airdrop failed');
  }

  private async sendWith(signers: Keypair[], ...ixs: Parameters<Transaction['add']>) {
    const tx = new Transaction().add(...ixs);
    tx.feePayer = signers[0].publicKey;
    tx.recentBlockhash = await this.latestBlockhash();
    tx.sign(...signers);
    return this.sendTransaction(tx);
  }

  async createMint(mint: Keypair, decimals: number, authority: Keypair) {
    const rent = this.svm.minimumBalanceForRentExemption(BigInt(MINT_SIZE)) as bigint;
    await this.sendWith(
      [authority, mint],
      SystemProgram.createAccount({
        fromPubkey: authority.publicKey,
        newAccountPubkey: mint.publicKey,
        lamports: Number(rent),
        space: MINT_SIZE,
        programId: TOKEN_PROGRAM_ID,
      }),
      createInitializeMint2Instruction(mint.publicKey, decimals, authority.publicKey, null),
    );
  }

  async mintTo(mint: PublicKey, owner: PublicKey, amount: bigint, authority: Keypair) {
    const ata = getAssociatedTokenAddressSync(mint, owner, true);
    await this.sendWith(
      [authority],
      createAssociatedTokenAccountIdempotentInstruction(authority.publicKey, ata, owner, mint),
      createMintToInstruction(mint, ata, authority.publicKey, amount),
    );
  }
}
