import { createPublicKey, verify as edVerify } from 'node:crypto';
import bs58 from 'bs58';
import { Keypair, PublicKey, Transaction, TransactionInstruction, VersionedTransaction } from '@solana/web3.js';
import { getAssociatedTokenAddressSync } from '@solana/spl-token';
import { decodeTransaction, type TokenAccountInfo } from './inspector.js';
import { KNOWN_PROGRAMS } from './programs.js';

/**
 * Where transactions settle. AgentWall talks to one of three ledgers:
 *
 *  - MemoryLedger:  a small in-process Solana simulator (pure TypeScript, runs anywhere).
 *                   It checks real ed25519 signatures and executes System, SPL Token,
 *                   Associated Token, Memo and Compute Budget instructions.
 *  - LiteSvmLedger: the real Solana runtime in-process via LiteSVM (Linux/macOS).
 *  - RpcLedger:     a real cluster (devnet or mainnet) over JSON-RPC.
 */
export interface Ledger {
  readonly kind: 'memory' | 'litesvm' | 'rpc';
  latestBlockhash(): Promise<string>;
  getSolBalance(owner: PublicKey): Promise<bigint>;
  getTokenBalance(owner: PublicKey, mint: PublicKey, tokenProgram?: PublicKey): Promise<bigint>;
  getTokenAccount(address: string): Promise<TokenAccountInfo | null>;
  /** Submit a fully signed transaction. Resolves with its signature once confirmed. */
  sendTransaction(tx: Transaction | VersionedTransaction): Promise<string>;
}

/** Ledgers you can seed with funds and mints (local development only). */
export interface DevLedger extends Ledger {
  airdrop(owner: PublicKey, lamports: bigint): Promise<void>;
  createMint(mint: Keypair, decimals: number, authority: Keypair): Promise<void>;
  mintTo(mint: PublicKey, owner: PublicKey, amount: bigint, authority: Keypair): Promise<void>;
}

export class LedgerError extends Error {}

export const ATA_RENT_LAMPORTS = 2_039_280n;
export const SIGNATURE_FEE_LAMPORTS = 5_000n;

interface MemTokenAccount {
  mint: string;
  owner: string;
  amount: bigint;
}

interface MemState {
  lamports: Map<string, bigint>;
  tokenAccounts: Map<string, MemTokenAccount>;
  mints: Map<string, { decimals: number; supply: bigint; authority: string }>;
}

function cloneState(s: MemState): MemState {
  return {
    lamports: new Map(s.lamports),
    tokenAccounts: new Map([...s.tokenAccounts].map(([k, v]) => [k, { ...v }])),
    mints: new Map([...s.mints].map(([k, v]) => [k, { ...v }])),
  };
}

function verifyEd25519(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean {
  const key = createPublicKey({
    key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(publicKey).toString('base64url') },
    format: 'jwk',
  });
  return edVerify(null, message, key, signature);
}

export class MemoryLedger implements DevLedger {
  readonly kind = 'memory' as const;
  private state: MemState = { lamports: new Map(), tokenAccounts: new Map(), mints: new Map() };
  private blockhashes: string[] = [];
  private seen = new Set<string>();

  constructor() {
    this.rotateBlockhash();
  }

  private rotateBlockhash() {
    const hash = bs58.encode(Keypair.generate().publicKey.toBytes());
    this.blockhashes.push(hash);
    if (this.blockhashes.length > 150) this.blockhashes.shift();
    return hash;
  }

  async latestBlockhash() {
    return this.blockhashes[this.blockhashes.length - 1];
  }

  async getSolBalance(owner: PublicKey) {
    return this.state.lamports.get(owner.toBase58()) ?? 0n;
  }

  async getTokenBalance(owner: PublicKey, mint: PublicKey) {
    const ata = getAssociatedTokenAddressSync(mint, owner, true).toBase58();
    return this.state.tokenAccounts.get(ata)?.amount ?? 0n;
  }

  async getTokenAccount(address: string) {
    const acc = this.state.tokenAccounts.get(address);
    return acc ? { mint: acc.mint, owner: acc.owner } : null;
  }

  async airdrop(owner: PublicKey, lamports: bigint) {
    const k = owner.toBase58();
    this.state.lamports.set(k, (this.state.lamports.get(k) ?? 0n) + lamports);
  }

  async createMint(mint: Keypair, decimals: number, authority: Keypair) {
    this.state.mints.set(mint.publicKey.toBase58(), { decimals, supply: 0n, authority: authority.publicKey.toBase58() });
  }

  async mintTo(mint: PublicKey, owner: PublicKey, amount: bigint, authority: Keypair) {
    const m = this.state.mints.get(mint.toBase58());
    if (!m) throw new LedgerError('Unknown mint');
    if (m.authority !== authority.publicKey.toBase58()) throw new LedgerError('Wrong mint authority');
    const ata = getAssociatedTokenAddressSync(mint, owner, true).toBase58();
    const acc = this.state.tokenAccounts.get(ata) ?? { mint: mint.toBase58(), owner: owner.toBase58(), amount: 0n };
    acc.amount += amount;
    m.supply += amount;
    this.state.tokenAccounts.set(ata, acc);
  }

  async sendTransaction(tx: Transaction | VersionedTransaction): Promise<string> {
    // 1. Signatures: every required signer must have produced a valid ed25519 signature.
    let message: Uint8Array;
    let sigs: { publicKey: string; signature: Uint8Array | null }[];
    let recentBlockhash: string;
    if (tx instanceof Transaction) {
      const msg = tx.compileMessage();
      message = msg.serialize();
      recentBlockhash = msg.recentBlockhash;
      const required = msg.accountKeys.slice(0, msg.header.numRequiredSignatures);
      sigs = required.map((pk) => ({
        publicKey: pk.toBase58(),
        signature: tx.signatures.find((s) => s.publicKey.equals(pk))?.signature ?? null,
      }));
    } else {
      message = tx.message.serialize();
      recentBlockhash = tx.message.recentBlockhash;
      const required = tx.message.staticAccountKeys.slice(0, tx.message.header.numRequiredSignatures);
      sigs = required.map((pk, i) => ({ publicKey: pk.toBase58(), signature: tx.signatures[i] ?? null }));
    }
    for (const s of sigs) {
      if (!s.signature || s.signature.every((b) => b === 0)) throw new LedgerError(`Missing signature for ${s.publicKey}`);
      if (!verifyEd25519(message, s.signature, new PublicKey(s.publicKey).toBytes())) {
        throw new LedgerError(`Invalid signature for ${s.publicKey}`);
      }
    }
    const signature = bs58.encode(sigs[0].signature!);
    if (this.seen.has(signature)) throw new LedgerError('Transaction already processed');
    if (!this.blockhashes.includes(recentBlockhash)) throw new LedgerError('Blockhash not found (expired)');

    // 2. Execute atomically on a copy of the state.
    const { feePayer, instructions } = decodeTransaction(tx);
    const signerSet = new Set(sigs.map((s) => s.publicKey));
    const next = cloneState(this.state);
    const debit = (who: string, lamports: bigint) => {
      const bal = next.lamports.get(who) ?? 0n;
      if (bal < lamports) throw new LedgerError(`Insufficient SOL in ${who}`);
      next.lamports.set(who, bal - lamports);
    };
    const credit = (who: string, lamports: bigint) => next.lamports.set(who, (next.lamports.get(who) ?? 0n) + lamports);

    debit(feePayer, SIGNATURE_FEE_LAMPORTS * BigInt(sigs.length));
    instructions.forEach((ix) => this.execute(ix, next, signerSet, debit, credit));

    this.state = next;
    this.seen.add(signature);
    this.rotateBlockhash();
    return signature;
  }

  private execute(
    ix: TransactionInstruction,
    s: MemState,
    signers: Set<string>,
    debit: (w: string, l: bigint) => void,
    credit: (w: string, l: bigint) => void,
  ) {
    const pid = ix.programId;
    const keys = ix.keys.map((k) => k.pubkey.toBase58());
    const data = Buffer.from(ix.data);
    const requireSigner = (k: string) => {
      if (!signers.has(k)) throw new LedgerError(`${k} must sign`);
    };

    if (pid.equals(KNOWN_PROGRAMS.system)) {
      if (data.length < 12 || data.readUInt32LE(0) !== 2) throw new LedgerError('Memory ledger only supports system transfers');
      requireSigner(keys[0]);
      const lamports = data.readBigUInt64LE(4);
      debit(keys[0], lamports);
      credit(keys[1], lamports);
      return;
    }
    if (pid.equals(KNOWN_PROGRAMS['associated-token'])) {
      const [payer, ata, owner, mint] = keys;
      const idempotent = data.length > 0 && data[0] === 1;
      const expected = getAssociatedTokenAddressSync(new PublicKey(mint), new PublicKey(owner), true).toBase58();
      if (expected !== ata) throw new LedgerError('Associated token address mismatch');
      if (!s.mints.has(mint)) throw new LedgerError(`Unknown mint ${mint}`);
      if (s.tokenAccounts.has(ata)) {
        if (!idempotent) throw new LedgerError('Associated token account already exists');
        return;
      }
      requireSigner(payer);
      debit(payer, ATA_RENT_LAMPORTS);
      credit(ata, ATA_RENT_LAMPORTS);
      s.tokenAccounts.set(ata, { mint, owner, amount: 0n });
      return;
    }
    if (pid.equals(KNOWN_PROGRAMS['spl-token'])) {
      const disc = data[0];
      let source: string, destination: string, authority: string, mint: string | undefined, decimals: number | undefined;
      if (disc === 3) [source, destination, authority] = keys;
      else if (disc === 12) {
        [source, mint, destination, authority] = keys;
        decimals = data[9];
      } else throw new LedgerError('Memory ledger only supports token transfers');
      const amount = data.readBigUInt64LE(1);
      const src = s.tokenAccounts.get(source);
      const dst = s.tokenAccounts.get(destination);
      if (!src) throw new LedgerError('Source token account not found');
      if (!dst) throw new LedgerError('Destination token account not found');
      if (src.mint !== dst.mint) throw new LedgerError('Mint mismatch');
      if (mint && mint !== src.mint) throw new LedgerError('Mint mismatch');
      if (decimals !== undefined && s.mints.get(src.mint)?.decimals !== decimals) throw new LedgerError('Decimals mismatch');
      if (src.owner !== authority) throw new LedgerError('Owner does not match');
      requireSigner(authority);
      if (src.amount < amount) throw new LedgerError('Insufficient token balance');
      src.amount -= amount;
      dst.amount += amount;
      return;
    }
    if (pid.equals(KNOWN_PROGRAMS.memo) || pid.equals(KNOWN_PROGRAMS['memo-v1'])) return;
    if (pid.equals(KNOWN_PROGRAMS['compute-budget'])) return;
    throw new LedgerError(`Program ${pid.toBase58()} is not supported by the memory ledger`);
  }
}
