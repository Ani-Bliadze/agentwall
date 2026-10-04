import { readFileSync } from 'node:fs';
import { PublicKey } from '@solana/web3.js';
import { z } from 'zod';
import { DLP_TYPES } from '../dlp/scanner.js';
import { KNOWN_PROGRAM_NAMES, type Network } from '../solana/programs.js';

const Address = z.string().refine(
  (v) => {
    try {
      new PublicKey(v);
      return true;
    } catch {
      return false;
    }
  },
  { message: 'Not a valid Solana address' },
);

export const DestinationSchema = z.object({
  address: Address,
  label: z.string().min(1),
});

export const MerchantSchema = z.object({
  name: z.string().min(1),
  /** Requests whose URL starts with this prefix belong to this merchant. */
  urlPrefix: z.string().url(),
  /** Pin the merchant's receiving wallet. A 402 quote asking to pay anyone else is rejected. */
  payTo: Address.optional(),
  maxPriceUsd: z.number().positive().optional(),
});

export const AssetSchema = z.object({
  decimals: z.number().int().min(0).max(18),
  /** Static USD price used to evaluate limits. Stablecoins are 1. */
  usdPrice: z.number().positive(),
  native: z.boolean().optional(),
  mints: z
    .object({
      'solana-local': Address.optional(),
      'solana-devnet': Address.optional(),
      solana: Address.optional(),
    })
    .prefault({}),
});

const ProgramRef = z.union([z.enum(KNOWN_PROGRAM_NAMES as [string, ...string[]]), Address]);

export const AgentPolicySchema = z.object({
  description: z.string().default(''),
  status: z.enum(['active', 'frozen']).default('active'),
  limits: z.object({
    perTransactionUsd: z.number().positive(),
    dailyUsd: z.number().positive(),
    maxTransactionsPerMinute: z.number().int().positive().default(10),
  }),
  approval: z
    .object({
      /** Escalate to a human when a single request is worth more than this. */
      aboveUsd: z.number().nonnegative().optional(),
      /** What to do with destinations that are not on the allowlist. */
      unknownDestinations: z.enum(['deny', 'require_approval']).default('deny'),
      timeoutSeconds: z.number().int().positive().default(900),
    })
    .prefault({}),
  assets: z.array(z.string()).min(1),
  destinations: z
    .object({
      allow: z.array(DestinationSchema).default([]),
      deny: z.array(DestinationSchema).default([]),
    })
    .prefault({}),
  x402: z
    .object({
      enabled: z.boolean().default(true),
      maxPriceUsd: z.number().positive().default(1),
      merchants: z.array(MerchantSchema).default([]),
    })
    .prefault({}),
  programs: z.array(ProgramRef).default(['system', 'spl-token', 'associated-token', 'memo', 'compute-budget']),
  dlp: z
    .object({
      block: z
        .array(z.enum(DLP_TYPES))
        .default(['solana_private_key', 'seed_phrase', 'evm_private_key', 'api_key', 'jwt', 'password', 'credit_card']),
      requireApproval: z.array(z.enum(DLP_TYPES)).default(['iban']),
    })
    .prefault({}),
  maxPriorityFeeMicroLamports: z.number().int().nonnegative().default(1_000_000),
});

export const PolicyFileSchema = z.object({
  version: z.literal(1),
  assets: z.record(z.string(), AssetSchema),
  global: z
    .object({
      denyDestinations: z.array(DestinationSchema).default([]),
    })
    .prefault({}),
  agents: z.record(z.string(), AgentPolicySchema),
});

export type Destination = z.infer<typeof DestinationSchema>;
export type Merchant = z.infer<typeof MerchantSchema>;
export type AssetConfig = z.infer<typeof AssetSchema>;
export type AgentPolicy = z.infer<typeof AgentPolicySchema>;
export type PolicyFile = z.infer<typeof PolicyFileSchema>;

export class PolicyError extends Error {}

export function parsePolicy(json: unknown): PolicyFile {
  const res = PolicyFileSchema.safeParse(json);
  if (!res.success) {
    const issues = res.error.issues.map((i) => `  - ${i.path.join('.')}: ${i.message}`).join('\n');
    throw new PolicyError(`Invalid policy file:\n${issues}`);
  }
  const policy = res.data;
  for (const [agentId, agent] of Object.entries(policy.agents)) {
    for (const symbol of agent.assets) {
      if (!policy.assets[symbol]) throw new PolicyError(`Agent "${agentId}" allows asset "${symbol}" which is not defined under "assets".`);
    }
  }
  return policy;
}

export function loadPolicyFile(path: string): PolicyFile {
  return parsePolicy(JSON.parse(readFileSync(path, 'utf8')));
}

export interface ResolvedAsset {
  symbol: string;
  decimals: number;
  usdPrice: number;
  native: boolean;
  mint: string | null;
}

/** Map a mint (or native SOL) back to the asset symbol configured for this network. */
export function assetByMint(policy: PolicyFile, network: Network, mint: string | null): ResolvedAsset | null {
  for (const [symbol, a] of Object.entries(policy.assets)) {
    if (mint === null && a.native) return { symbol, decimals: a.decimals, usdPrice: a.usdPrice, native: true, mint: null };
    if (mint && a.mints[network] === mint) return { symbol, decimals: a.decimals, usdPrice: a.usdPrice, native: false, mint };
  }
  return null;
}

export function assetBySymbol(policy: PolicyFile, network: Network, symbol: string): ResolvedAsset | null {
  const a = policy.assets[symbol];
  if (!a) return null;
  if (a.native) return { symbol, decimals: a.decimals, usdPrice: a.usdPrice, native: true, mint: null };
  const mint = a.mints[network];
  if (!mint) return null;
  return { symbol, decimals: a.decimals, usdPrice: a.usdPrice, native: false, mint };
}
