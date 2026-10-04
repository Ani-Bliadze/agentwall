import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Keypair, LAMPORTS_PER_SOL, PublicKey } from '@solana/web3.js';
import { AuditLog } from '../audit/log.js';
import { AgentWall } from '../core/agentwall.js';
import { DEMO } from '../demo/identities.js';
import { demoMerchantRouter } from '../demo/merchant.js';
import { loadPolicyFile, parsePolicy, type PolicyFile } from '../policy/schema.js';
import { MemoryLedger, type DevLedger, type Ledger } from '../solana/ledger.js';
import { LiteSvmLedger } from '../solana/litesvm-ledger.js';
import type { Network } from '../solana/programs.js';
import { RpcLedger } from '../solana/rpc-ledger.js';
import { createApp } from './app.js';

export interface BootstrapOptions {
  network?: Network;
  /** For solana-local: which simulator to use. */
  ledger?: 'memory' | 'litesvm';
  rpcUrl?: string;
  policy?: PolicyFile | string;
  keypairPath?: string;
  /** Directory for the audit log. Omit to keep everything in memory. */
  dataDir?: string;
  port?: number;
  host?: string;
  adminToken?: string;
  /** "agent-id:api-key,agent-id:api-key". Random keys are generated when omitted. */
  agentKeys?: string;
  /** Mount the demo x402 merchants and seed local balances. */
  demo?: boolean;
  quiet?: boolean;
}

export interface Running {
  wall: AgentWall;
  url: string;
  adminToken: string;
  agentKeys: Record<string, string>;
  server: Server;
  close(): Promise<void>;
}

const DEFAULT_POLICY = new URL('../../policies/demo.policy.json', import.meta.url);

function loadKeypair(path: string): Keypair {
  return Keypair.fromSecretKey(Uint8Array.from(JSON.parse(readFileSync(path, 'utf8')) as number[]));
}

function parseAgentKeys(spec: string | undefined, agents: string[]): Map<string, string> {
  const map = new Map<string, string>();
  if (spec) {
    for (const pair of spec.split(',').map((s) => s.trim()).filter(Boolean)) {
      const i = pair.indexOf(':');
      if (i < 1) throw new Error(`Bad AGENTWALL_AGENT_KEYS entry "${pair}" (expected agent-id:key)`);
      map.set(pair.slice(i + 1), pair.slice(0, i));
    }
  } else {
    for (const id of agents) map.set(`aw_${id.replace(/[^a-z0-9]/gi, '')}_${randomBytes(12).toString('hex')}`, id);
  }
  return map;
}

/** Seed the local ledger: SOL for fees, a local USDC mint, and balances for the demo. */
async function seedLocal(ledger: DevLedger, custody: Keypair) {
  const authority = DEMO.mintAuthority();
  await ledger.airdrop(authority.publicKey, 10n * BigInt(LAMPORTS_PER_SOL));
  await ledger.airdrop(custody.publicKey, 5n * BigInt(LAMPORTS_PER_SOL));
  await ledger.airdrop(DEMO.facilitator().publicKey, 2n * BigInt(LAMPORTS_PER_SOL));
  await ledger.createMint(DEMO.usdcMint(), 6, authority);
  await ledger.mintTo(DEMO.usdcMint().publicKey, custody.publicKey, 1_000_000_000n, authority); // 1,000 USDC
  await ledger.createMint(DEMO.mysteryMint(), 6, authority);
  await ledger.mintTo(DEMO.mysteryMint().publicKey, custody.publicKey, 5_000_000_000n, authority); // an unlisted token
}

export async function startAgentWall(opts: BootstrapOptions = {}): Promise<Running> {
  const network: Network = opts.network ?? 'solana-local';
  const port = opts.port ?? 8787;
  const host = opts.host ?? 'localhost';
  const log = opts.quiet ? () => {} : (...a: unknown[]) => console.log(...a);

  // Policy -------------------------------------------------------------------
  let policy: PolicyFile;
  if (typeof opts.policy === 'object') policy = parsePolicy(structuredClone(opts.policy));
  else policy = loadPolicyFile(opts.policy ?? fileURLToPath(DEFAULT_POLICY));

  // Wallet -------------------------------------------------------------------
  let custody: Keypair;
  if (opts.keypairPath) custody = loadKeypair(opts.keypairPath);
  else if (network === 'solana-local') custody = DEMO.custody();
  else {
    const dir = opts.dataDir ?? 'data';
    const path = join(dir, 'custody-keypair.json');
    if (!existsSync(path)) {
      mkdirSync(dir, { recursive: true });
      writeFileSync(path, JSON.stringify(Array.from(Keypair.generate().secretKey)), { mode: 0o600 });
      log(`Generated a new custody wallet at ${path}. Fund it before sending payments.`);
    }
    custody = loadKeypair(path);
  }

  // Ledger -------------------------------------------------------------------
  let ledger: Ledger;
  if (network === 'solana-local') {
    const dev: DevLedger = opts.ledger === 'litesvm' ? await LiteSvmLedger.create() : new MemoryLedger();
    await seedLocal(dev, custody);
    ledger = dev;
  } else {
    const rpc = opts.rpcUrl ?? (network === 'solana-devnet' ? 'https://api.devnet.solana.com' : 'https://api.mainnet-beta.solana.com');
    ledger = new RpcLedger(rpc);
  }

  const audit = new AuditLog(opts.dataDir ? join(opts.dataDir, `audit-${network}.jsonl`) : undefined);
  const wall = new AgentWall({ policy, ledger, custody, network, audit });
  const adminToken = opts.adminToken ?? `aw_admin_${randomBytes(16).toString('hex')}`;
  const agentKeys = parseAgentKeys(opts.agentKeys, Object.keys(policy.agents));

  let baseUrl = `http://localhost:${port}`;
  const app = createApp({
    wall,
    agentKeys,
    adminToken,
    mount: (a) => {
      if (!opts.demo) return;
      const usdc = policy.assets.USDC?.mints[network];
      if (!usdc) throw new Error(`Demo merchants need a USDC mint for ${network} in the policy file.`);
      a.use(
        '/demo',
        demoMerchantRouter({
          ledger,
          network,
          usdcMint: new PublicKey(usdc),
          facilitator: DEMO.facilitator(),
          weatherPayTo: DEMO.weatherMerchant().publicKey,
          gpuPayTo: DEMO.gpuMarket().publicKey,
          attacker: DEMO.attacker().publicKey,
          baseUrl: () => baseUrl,
        }),
      );
    },
  });

  const server = await new Promise<Server>((resolve, reject) => {
    const s = app.listen(port, host, () => resolve(s));
    s.on('error', reject);
  });
  const actualPort = (server.address() as AddressInfo).port;
  baseUrl = `http://localhost:${actualPort}`;
  if (opts.demo && actualPort !== 8787) {
    // The demo policy names merchants on port 8787; follow the real port.
    for (const a of Object.values(policy.agents)) {
      for (const m of a.x402.merchants) m.urlPrefix = m.urlPrefix.replace('http://localhost:8787', baseUrl);
    }
  }
  audit.append('system.started', { network, ledger: ledger.kind, wallet: custody.publicKey.toBase58() });

  return {
    wall,
    url: baseUrl,
    adminToken,
    agentKeys: Object.fromEntries([...agentKeys].map(([key, id]) => [id, key])),
    server,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections?.();
        server.close(() => resolve());
      }),
  };
}
