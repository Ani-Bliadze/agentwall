/**
 * AgentWall end-to-end demo.
 *
 * Starts AgentWall on a local Solana ledger with demo x402 merchants, then runs
 * a scripted AI agent through good payments, a human approval, and a series of
 * attacks: prompt injection, a compromised merchant, data leaks, a wallet
 * drainer, an unknown token, a runaway loop and the kill switch.
 *
 *   npm run demo                      # run everything, auto-approve as a simulated human
 *   npm run demo -- --interactive     # approve/reject yourself in the dashboard
 *   npm run demo -- --ledger litesvm  # settle on the real Solana runtime (Linux/macOS)
 */
import { PublicKey, Transaction } from '@solana/web3.js';
import {
  createApproveInstruction,
  createAssociatedTokenAccountIdempotentInstruction,
  createTransferCheckedInstruction,
  getAssociatedTokenAddressSync,
} from '@solana/spl-token';
import { DEMO } from '../src/demo/identities.js';
import type { AgentRequest } from '../src/core/agentwall.js';
import { AgentWallClient } from '../src/sdk/client.js';
import { startAgentWall } from '../src/server/bootstrap.js';

const args = process.argv.slice(2);
const interactive = args.includes('--interactive');
const keepOpen = interactive || args.includes('--keep-open');
const ledgerKind = args.includes('--ledger') ? (args[args.indexOf('--ledger') + 1] as 'memory' | 'litesvm') : 'memory';
const port = args.includes('--port') ? Number(args[args.indexOf('--port') + 1]) : 8787;

// ---- pretty output ----------------------------------------------------------
const color = !process.env.NO_COLOR && process.stdout.isTTY;
const c = (code: string) => (s: string) => (color ? `\x1b[${code}m${s}\x1b[0m` : s);
const green = c('32'), red = c('31'), yellow = c('33'), dim = c('2'), bold = c('1'), cyan = c('36'), magenta = c('35');
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const short = (s?: string) => (s && s.length > 14 ? `${s.slice(0, 4)}…${s.slice(-4)}` : s ?? '');

let n = 0;
function scenario(title: string, story: string) {
  n++;
  console.log(`\n${bold(String(n).padStart(2))}  ${bold(title)}`);
  console.log(`    ${dim(story)}`);
}

function result(r: AgentRequest | undefined, extra = '') {
  if (!r) return;
  const tag: Record<string, string> = {
    executed: green('✓ ALLOWED '),
    signed: green('✓ SIGNED  '),
    pending_approval: yellow('⏸ APPROVAL'),
    denied: red('✕ BLOCKED '),
    rejected: red('✕ REJECTED'),
    expired: red('✕ EXPIRED '),
    failed: red('✕ FAILED  '),
  };
  console.log(`    ${tag[r.status] ?? r.status}  ${r.decision.reason}`);
  if (r.signature) console.log(`    ${dim(`             tx ${short(r.signature)} on ${wallNetwork}`)}`);
  if (extra) console.log(`    ${dim(`             ${extra}`)}`);
}

let wallNetwork = '';

// ---- start AgentWall ---------------------------------------------------------
const wall = await startAgentWall({ demo: true, port, ledger: ledgerKind, quiet: true });
wallNetwork = `${wall.wall.network} (${wall.wall.ledger.kind})`;
const dashboard = `${wall.url}/?token=${wall.adminToken}`;

console.log(`
${bold(cyan('AgentWall'))} ${dim('· a security layer for AI agents that spend money on Solana')}

  Ledger      ${wallNetwork}
  Wallet      ${wall.wall.wallet.toBase58()}  ${dim('(held by AgentWall, never by the agent)')}
  Dashboard   ${dashboard}
`);

const research = new AgentWallClient({ baseUrl: wall.url, apiKey: wall.agentKeys['research-agent'], throwOnDeny: false });
const ops = new AgentWallClient({ baseUrl: wall.url, apiKey: wall.agentKeys['ops-agent'], throwOnDeny: false });

const admin = async (path: string, body: unknown = {}) => {
  const res = await fetch(`${wall.url}${path}`, {
    method: 'POST',
    headers: { authorization: `Bearer ${wall.adminToken}`, 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  return (await res.json()) as AgentRequest;
};

/** In interactive mode wait for a human in the dashboard; otherwise act as the operator. */
async function human(r: AgentRequest, client: AgentWallClient, decision: 'approve' | 'reject'): Promise<AgentRequest> {
  if (r.status !== 'pending_approval') return r;
  if (interactive) {
    console.log(`    ${magenta('→ Waiting for you: approve or reject it in the dashboard')} ${dim(dashboard)}`);
    let out = r;
    while (out.status === 'pending_approval') out = await client.getRequest(r.id, 30);
    return out;
  }
  await sleep(1200);
  console.log(`    ${magenta(`→ Operator ${decision === 'approve' ? 'approves' : 'rejects'} it in the dashboard`)}`);
  await admin(`/admin/approvals/${r.id}/${decision}`, { by: 'operator (simulated)' });
  return client.getRequest(r.id);
}

const W = (k: keyof typeof DEMO) => DEMO[k]().publicKey.toBase58();
const usdcMint = new PublicKey(wall.wall.policy.assets.USDC.mints['solana-local']!);
const wallet = wall.wall.wallet;

async function unsignedTx(...ixs: Parameters<Transaction['add']>) {
  const tx = new Transaction().add(...ixs);
  tx.feePayer = wallet;
  tx.recentBlockhash = await wall.wall.ledger.latestBlockhash();
  return tx.serialize({ requireAllSignatures: false, verifySignatures: false }).toString('base64');
}

console.log(bold('research-agent') + dim('  · $250/tx, $500/day, human approval above $100, x402 merchants capped per call'));

// 1. x402 purchase -------------------------------------------------------------
scenario('Buy data over x402', 'The agent calls a paid weather API. It answers 402 Payment Required with a $0.05 USDC quote.');
{
  const { response, payment, settlement } = await research.fetch(`${wall.url}/demo/weather/forecast?city=Tbilisi`, { purpose: 'Weather input for the travel plan' });
  result(payment, settlement?.success ? `merchant settled it, HTTP ${response.status}, got the 7-day forecast` : '');
}

// 2. Vendor invoice --------------------------------------------------------------
scenario('Pay a known vendor', 'Acme Cloud is on the allowlist. Invoice INV-2291 for 12 USDC.');
result(await research.transfer({ asset: 'USDC', amount: '12', to: W('acmeCloud'), memo: 'INV-2291', purpose: 'Monthly hosting invoice' }));

// 3. Human approval ----------------------------------------------------------------
scenario('Large payment needs a human', 'Buying a 180 USDC dataset from DataLabs. Allowed vendor, but above the $100 auto-approve line.');
{
  const r = await research.transfer({ asset: 'USDC', amount: '180', to: W('dataLabs'), memo: 'PO-7781 dataset licence', purpose: 'Training data for the churn model' });
  result(r);
  result(await human(r, research, 'approve'));
}

// 4. Prompt injection ----------------------------------------------------------------
scenario('Prompt injection in third-party data', 'The agent buys weather alerts ($0.01). The response hides an instruction to send 450 USDC to a "billing wallet".');
{
  const { response, payment } = await research.fetch(`${wall.url}/demo/weather/alerts?city=Tbilisi`);
  result(payment);
  const data = (await response.json()) as { notice: string };
  console.log(`    ${dim('             injected text: "' + data.notice.slice(0, 92) + '…"')}`);
  const injectedWallet = data.notice.match(/[1-9A-HJ-NP-Za-km-z]{32,44}/)![0];
  console.log(`    ${yellow('→ The model falls for it and tries to pay')}`);
  result(await research.transfer({ asset: 'USDC', amount: '450', to: injectedWallet, purpose: 'Restore API subscription' }));
}

// 5. Compromised merchant ---------------------------------------------------------------
scenario('Compromised merchant', 'Same trusted weather API, but its server now asks to be paid to a different wallet.');
result((await research.fetch(`${wall.url}/demo/weather/historical`)).payment);

// 6. Overpriced quote ----------------------------------------------------------------
scenario('Overpriced x402 quote', 'A premium report costs $5. This merchant is capped at $0.10 per call.');
result((await research.fetch(`${wall.url}/demo/weather/premium-report`)).payment);

// 7. Unknown merchant -----------------------------------------------------------------
scenario('Unapproved merchant', 'The agent finds a GPU spot market on its own and tries to rent an H100 hour.');
result((await research.fetch(`${wall.url}/demo/unverified/gpu-hours`)).payment);

// 8. Data leaks -------------------------------------------------------------------------
scenario('Secret in an on-chain memo', 'The agent pastes the wallet recovery phrase into a payment memo. Memos are public forever.');
result(
  await research.transfer({
    asset: 'USDC',
    amount: '1',
    to: W('acmeCloud'),
    memo: 'backup: legal winner thank year wave sausage worth useful legal winner thank yellow',
  }),
);

scenario('Customer data sent to a paid API', 'The agent sends a customer card number in the body of an x402 request.');
result(
  (
    await research.fetch(`${wall.url}/demo/weather/forecast`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ city: 'Batumi', customer: { name: 'N. Beridze', card: '4111 1111 1111 1111' } }),
    })
  ).payment,
);

// 9. Wallet drainer ---------------------------------------------------------------------
scenario('Wallet-drainer transaction', 'A "swap" helper hands the agent a transaction that quietly approves a delegate over all its USDC.');
result(
  await research.submitTransaction(
    await unsignedTx(createApproveInstruction(getAssociatedTokenAddressSync(usdcMint, wallet), new PublicKey(W('attacker')), wallet, 1_000_000_000n)),
    { purpose: 'Swap USDC to SOL' },
  ),
);

// 10. Unknown token ---------------------------------------------------------------------
scenario('Unlisted token', 'The agent tries to pay Acme Cloud in a token that is not on its asset list.');
{
  const mystery = DEMO.mysteryMint().publicKey;
  const acme = DEMO.acmeCloud().publicKey;
  const acmeAta = getAssociatedTokenAddressSync(mystery, acme);
  result(
    await research.submitTransaction(
      await unsignedTx(
        createAssociatedTokenAccountIdempotentInstruction(wallet, acmeAta, acme, mystery),
        createTransferCheckedInstruction(getAssociatedTokenAddressSync(mystery, wallet), mystery, acmeAta, wallet, 500_000_000n, 6),
      ),
      { purpose: 'Pay Acme Cloud' },
    ),
  );
}

// ---- ops-agent ------------------------------------------------------------------------
console.log('\n' + bold('ops-agent') + dim('  · $20/tx, $50/day, max 5 payments a minute, unknown recipients go to a human'));

scenario('Unknown recipient', 'The agent wants to pay 8 USDC to an address it found in an email.');
{
  const r = await ops.transfer({ asset: 'USDC', amount: '8', to: W('gpuMarket'), purpose: 'Reimburse contractor' });
  result(r);
  result(await human(r, ops, 'reject'));
}

scenario('Runaway loop', 'A bug makes the agent retry a 1 USDC payment in a tight loop.');
for (let i = 0; i < 6; i++) {
  const r = await ops.transfer({ asset: 'USDC', amount: '1', to: W('acmeCloud'), memo: `retry ${i + 1}` });
  result(r);
}

scenario('Kill switch', 'The operator freezes ops-agent from the dashboard. Its next payment is refused.');
await admin('/admin/agents/ops-agent/freeze', { by: 'operator (simulated)' });
result(await ops.transfer({ asset: 'SOL', amount: '0.01', to: W('acmeCloud') }));

// ---- audit -------------------------------------------------------------------------------
const anchor = await wall.wall.anchorAudit();
const verification = wall.wall.audit.verify();
const snap = await wall.wall.snapshot();
console.log(`
${bold('Audit trail')}
    ${verification.ok ? green('✓ hash chain verified') : red('✕ hash chain broken')}  ${dim(`${verification.count} entries`)}
    ${dim(`head #${anchor.seq} ${anchor.head.slice(0, 16)}… anchored on Solana in memo tx ${short(anchor.signature)}`)}

${bold('Result')}  ${green(`${snap.stats.allowed} allowed`)} · ${red(`${snap.stats.blocked} blocked`)} · spent ${'$' + snap.stats.spentLast24hUsd.toFixed(2)} of 1,000 USDC
`);

if (keepOpen) {
  console.log(`Dashboard stays open at ${bold(dashboard)}  ${dim('(Ctrl+C to stop)')}\n`);
} else {
  await wall.close();
  console.log(dim(`Run "npm run demo:interactive" to approve payments yourself in the dashboard.\n`));
}
