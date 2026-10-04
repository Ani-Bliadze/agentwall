import {
  PublicKey,
  Transaction,
  TransactionInstruction,
  TransactionMessage,
  VersionedTransaction,
} from '@solana/web3.js';
import { KNOWN_PROGRAMS, programName } from './programs.js';

/**
 * Transaction inspector.
 *
 * AgentWall never trusts what an agent *says* a transaction does. It decodes
 * the exact bytes it is being asked to sign, instruction by instruction, and
 * turns them into transfers, memos and risk flags the policy engine can judge.
 */

export type InstructionRisk = 'safe' | 'dangerous' | 'unsupported' | 'unknown_program';

export interface DecodedInstruction {
  index: number;
  programId: string;
  program: string;
  name: string;
  risk: InstructionRisk;
  note?: string;
}

export interface RawTransfer {
  index: number;
  kind: 'sol' | 'spl';
  amount: bigint;
  /** The key that authorizes the transfer (must sign). */
  authority: string;
  /** Wallet for SOL, token account for SPL. */
  source: string;
  /** Wallet for SOL, token account for SPL. */
  destination: string;
  mint?: string;
  decimals?: number;
  tokenProgram?: string;
}

export interface ResolvedTransfer extends RawTransfer {
  /** Wallet that ends up owning the funds. null when it cannot be determined. */
  destinationOwner: string | null;
}

export interface TokenAccountInfo {
  mint: string;
  owner: string;
}

export type TokenAccountResolver = (address: string) => Promise<TokenAccountInfo | null>;

export interface InspectedTransaction {
  feePayer: string;
  signers: string[];
  instructions: DecodedInstruction[];
  transfers: ResolvedTransfer[];
  memos: string[];
  computeUnitPriceMicroLamports?: bigint;
  computeUnitLimit?: number;
  warnings: string[];
}

const SYSTEM = KNOWN_PROGRAMS.system.toBase58();
const TOKEN = KNOWN_PROGRAMS['spl-token'].toBase58();
const TOKEN_2022 = KNOWN_PROGRAMS['token-2022'].toBase58();
const ATA = KNOWN_PROGRAMS['associated-token'].toBase58();
const MEMO = KNOWN_PROGRAMS.memo.toBase58();
const MEMO_V1 = KNOWN_PROGRAMS['memo-v1'].toBase58();
const COMPUTE = KNOWN_PROGRAMS['compute-budget'].toBase58();

const SYSTEM_IX: Record<number, [string, InstructionRisk, string?]> = {
  0: ['createAccount', 'unsupported'],
  1: ['assign', 'dangerous', 'Changes the program that owns an account. A classic wallet-drain primitive.'],
  2: ['transfer', 'safe'],
  3: ['createAccountWithSeed', 'unsupported'],
  4: ['advanceNonceAccount', 'safe'],
  5: ['withdrawNonceAccount', 'unsupported'],
  6: ['initializeNonceAccount', 'unsupported'],
  7: ['authorizeNonceAccount', 'dangerous', 'Hands control of a durable nonce to another key.'],
  8: ['allocate', 'unsupported'],
  9: ['allocateWithSeed', 'unsupported'],
  10: ['assignWithSeed', 'dangerous', 'Changes the owner program of an account.'],
  11: ['transferWithSeed', 'unsupported'],
};

const TOKEN_IX: Record<number, [string, InstructionRisk, string?]> = {
  0: ['initializeMint', 'unsupported'],
  1: ['initializeAccount', 'unsupported'],
  3: ['transfer', 'safe'],
  4: ['approve', 'dangerous', 'Grants a delegate the right to move tokens later, outside AgentWall.'],
  5: ['revoke', 'safe'],
  6: ['setAuthority', 'dangerous', 'Transfers ownership of a token account or mint to another key.'],
  7: ['mintTo', 'unsupported'],
  8: ['burn', 'dangerous', 'Destroys tokens.'],
  9: ['closeAccount', 'dangerous', 'Closes a token account and sends its rent to an arbitrary address.'],
  10: ['freezeAccount', 'unsupported'],
  11: ['thawAccount', 'unsupported'],
  12: ['transferChecked', 'safe'],
  13: ['approveChecked', 'dangerous', 'Grants a delegate the right to move tokens later, outside AgentWall.'],
  14: ['mintToChecked', 'unsupported'],
  15: ['burnChecked', 'dangerous', 'Destroys tokens.'],
  17: ['syncNative', 'safe'],
};

function readU64(data: Uint8Array, offset: number): bigint {
  return Buffer.from(data).readBigUInt64LE(offset);
}

export function decodeTransaction(input: string | Uint8Array | Transaction | VersionedTransaction): {
  feePayer: string;
  signers: string[];
  instructions: TransactionInstruction[];
  warnings: string[];
} {
  const warnings: string[] = [];
  if (input instanceof Transaction) {
    const msg = input.compileMessage();
    const signers = msg.accountKeys.slice(0, msg.header.numRequiredSignatures).map((k) => k.toBase58());
    return { feePayer: msg.accountKeys[0].toBase58(), signers, instructions: input.instructions, warnings };
  }
  const vtx =
    input instanceof VersionedTransaction
      ? input
      : VersionedTransaction.deserialize(typeof input === 'string' ? Buffer.from(input, 'base64') : input);
  const message = vtx.message;
  if (message.addressTableLookups.length > 0) {
    throw new InspectionError(
      'Transactions that use address lookup tables are not supported yet: every account must be visible to the policy engine.',
    );
  }
  const keys = message.staticAccountKeys;
  const signers = keys.slice(0, message.header.numRequiredSignatures).map((k) => k.toBase58());
  const decompiled = TransactionMessage.decompile(message);
  return { feePayer: decompiled.payerKey.toBase58(), signers, instructions: decompiled.instructions, warnings };
}

export class InspectionError extends Error {}

export async function inspectTransaction(
  input: string | Uint8Array | Transaction | VersionedTransaction,
  resolveTokenAccount: TokenAccountResolver,
): Promise<InspectedTransaction> {
  const { feePayer, signers, instructions, warnings } = decodeTransaction(input);
  const decoded: DecodedInstruction[] = [];
  const raw: RawTransfer[] = [];
  const memos: string[] = [];
  const createdAtas = new Map<string, TokenAccountInfo>();
  let computeUnitPriceMicroLamports: bigint | undefined;
  let computeUnitLimit: number | undefined;

  instructions.forEach((ix, index) => {
    const programId = ix.programId.toBase58();
    const name = programName(programId);
    const data = ix.data;
    const keys = ix.keys.map((k) => k.pubkey.toBase58());
    const push = (n: string, risk: InstructionRisk, note?: string) =>
      decoded.push({ index, programId, program: name ?? programId, name: n, risk, note });

    if (programId === SYSTEM) {
      const disc = data.length >= 4 ? Buffer.from(data).readUInt32LE(0) : -1;
      const [n, risk, note] = SYSTEM_IX[disc] ?? ['unknown', 'unsupported'];
      push(n, risk, note);
      if (disc === 2 && data.length >= 12) {
        raw.push({ index, kind: 'sol', amount: readU64(data, 4), authority: keys[0], source: keys[0], destination: keys[1] });
      }
      return;
    }

    if (programId === TOKEN || programId === TOKEN_2022) {
      const disc = data.length > 0 ? data[0] : -1;
      const [n, risk, note] = TOKEN_IX[disc] ?? ['unknown', 'unsupported'];
      push(n, risk, note);
      if (disc === 3 && data.length >= 9) {
        raw.push({ index, kind: 'spl', amount: readU64(data, 1), source: keys[0], destination: keys[1], authority: keys[2], tokenProgram: programId });
      } else if (disc === 12 && data.length >= 10) {
        raw.push({
          index,
          kind: 'spl',
          amount: readU64(data, 1),
          decimals: data[9],
          source: keys[0],
          mint: keys[1],
          destination: keys[2],
          authority: keys[3],
          tokenProgram: programId,
        });
      }
      return;
    }

    if (programId === ATA) {
      const disc = data.length === 0 ? 0 : data[0];
      if (disc === 0 || disc === 1) {
        push(disc === 0 ? 'createAssociatedTokenAccount' : 'createAssociatedTokenAccountIdempotent', 'safe');
        createdAtas.set(keys[1], { owner: keys[2], mint: keys[3] });
      } else {
        push('recoverNested', 'unsupported');
      }
      return;
    }

    if (programId === MEMO || programId === MEMO_V1) {
      push('memo', 'safe');
      memos.push(Buffer.from(data).toString('utf8'));
      return;
    }

    if (programId === COMPUTE) {
      const disc = data.length > 0 ? data[0] : -1;
      if (disc === 2 && data.length >= 5) {
        computeUnitLimit = Buffer.from(data).readUInt32LE(1);
        push('setComputeUnitLimit', 'safe');
      } else if (disc === 3 && data.length >= 9) {
        computeUnitPriceMicroLamports = readU64(data, 1);
        push('setComputeUnitPrice', 'safe');
      } else {
        push('computeBudget', 'safe');
      }
      return;
    }

    push('unknown', 'unknown_program', 'AgentWall cannot decode this program, so it cannot know what signing it would do.');
  });

  const resolve = async (address: string): Promise<TokenAccountInfo | null> =>
    createdAtas.get(address) ?? (await resolveTokenAccount(address));

  const transfers: ResolvedTransfer[] = [];
  for (const t of raw) {
    if (t.kind === 'sol') {
      transfers.push({ ...t, destinationOwner: t.destination });
      continue;
    }
    const dest = await resolve(t.destination);
    let mint = t.mint;
    if (!mint) {
      const src = await resolve(t.source);
      mint = src?.mint ?? dest?.mint;
      if (!mint) warnings.push(`Could not determine the mint of token transfer #${t.index}.`);
    }
    if (dest && mint && dest.mint !== mint) {
      warnings.push(`Destination token account of transfer #${t.index} holds a different mint than the one being sent.`);
    }
    transfers.push({ ...t, mint, destinationOwner: dest?.owner ?? null });
  }

  return { feePayer, signers, instructions: decoded, transfers, memos, computeUnitPriceMicroLamports, computeUnitLimit, warnings };
}

export function shortAddress(address: string | PublicKey | null | undefined): string {
  if (!address) return 'unknown';
  const s = typeof address === 'string' ? address : address.toBase58();
  return s.length > 12 ? `${s.slice(0, 4)}…${s.slice(-4)}` : s;
}
