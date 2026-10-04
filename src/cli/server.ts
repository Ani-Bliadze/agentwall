import { existsSync } from 'node:fs';
import { NETWORKS, type Network } from '../solana/programs.js';
import { startAgentWall } from '../server/bootstrap.js';

if (existsSync('.env')) process.loadEnvFile('.env');

const env = process.env;
const network = (env.AGENTWALL_NETWORK ?? 'solana-local') as Network;
if (!NETWORKS.includes(network)) {
  console.error(`AGENTWALL_NETWORK must be one of: ${NETWORKS.join(', ')}`);
  process.exit(1);
}

const running = await startAgentWall({
  network,
  ledger: (env.AGENTWALL_LEDGER as 'memory' | 'litesvm' | undefined) ?? 'memory',
  rpcUrl: env.AGENTWALL_RPC_URL,
  policy: env.AGENTWALL_POLICY,
  keypairPath: env.AGENTWALL_KEYPAIR,
  dataDir: env.AGENTWALL_DATA_DIR ?? 'data',
  port: env.PORT ? Number(env.PORT) : 8787,
  host: env.HOST,
  adminToken: env.AGENTWALL_ADMIN_TOKEN,
  agentKeys: env.AGENTWALL_AGENT_KEYS,
  demo: env.AGENTWALL_DEMO === '1' || network === 'solana-local',
});

console.log(`
  AgentWall is running
  ─────────────────────────────────────────────
  Network     ${running.wall.network} (${running.wall.ledger.kind} ledger)
  Wallet      ${running.wall.wallet.toBase58()}
  Dashboard   ${running.url}/?token=${running.adminToken}
  Agent API   ${running.url}/v1
${Object.entries(running.agentKeys)
  .map(([id, key]) => `  Agent key   ${id.padEnd(16)} ${key}`)
  .join('\n')}
`);

const shutdown = async () => {
  await running.close();
  process.exit(0);
};
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
