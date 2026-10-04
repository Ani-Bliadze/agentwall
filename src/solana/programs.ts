import { ComputeBudgetProgram, PublicKey, SystemProgram } from '@solana/web3.js';
import { ASSOCIATED_TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID } from '@solana/spl-token';

export const MEMO_PROGRAM_ID = new PublicKey('MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr');
export const MEMO_V1_PROGRAM_ID = new PublicKey('Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo');

/** Programs AgentWall knows how to decode. Policies allow them by these names. */
export const KNOWN_PROGRAMS = {
  system: SystemProgram.programId,
  'spl-token': TOKEN_PROGRAM_ID,
  'token-2022': TOKEN_2022_PROGRAM_ID,
  'associated-token': ASSOCIATED_TOKEN_PROGRAM_ID,
  memo: MEMO_PROGRAM_ID,
  'memo-v1': MEMO_V1_PROGRAM_ID,
  'compute-budget': ComputeBudgetProgram.programId,
} as const;

export type KnownProgramName = keyof typeof KNOWN_PROGRAMS;
export const KNOWN_PROGRAM_NAMES = Object.keys(KNOWN_PROGRAMS) as KnownProgramName[];

const BY_ADDRESS = new Map<string, KnownProgramName>(
  Object.entries(KNOWN_PROGRAMS).map(([name, id]) => [id.toBase58(), name as KnownProgramName]),
);

export function programName(programId: PublicKey | string): KnownProgramName | null {
  const key = typeof programId === 'string' ? programId : programId.toBase58();
  return BY_ADDRESS.get(key) ?? null;
}

export const NETWORKS = ['solana-local', 'solana-devnet', 'solana'] as const;
export type Network = (typeof NETWORKS)[number];
