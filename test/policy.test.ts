import { describe, expect, it } from 'vitest';
import { Keypair, PublicKey, Transaction } from '@solana/web3.js';
import { getAssociatedTokenAddressSync } from '@solana/spl-token';
import { AuditLog } from '../src/audit/log.js';
import { AgentWall } from '../src/core/agentwall.js';
import { DEMO } from '../src/demo/identities.js';
import { memoInstruction } from '../src/solana/builder.js';
import type { PaymentRequirements } from '../src/x402/types.js';
import { addr, demoPolicy, seededLedger } from './helpers.js';

async function setup(mutate?: (p: ReturnType<typeof demoPolicy>) => void) {
  const policy = demoPolicy();
  mutate?.(policy);
  const ledger = await seededLedger();
  const wall = new AgentWall({ policy, ledger, custody: DEMO.custody(), network: 'solana-local', audit: new AuditLog() });
  return { wall, ledger };
}

const failed = (r: { decision: { checks: { rule: string; outcome: string }[] } }) =>
  r.decision.checks.filter((c) => c.outcome === 'deny' || c.outcome === 'require_approval').map((c) => c.rule);

describe('policy engine', () => {
  it('allows and executes a payment to an allowlisted vendor', async () => {
    const { wall, ledger } = await setup();
    const r = await wall.transfer('research-agent', { asset: 'USDC', amount: '12.5', to: addr('acmeCloud') });
    expect(r.status).toBe('executed');
    expect(await ledger.getTokenBalance(DEMO.acmeCloud().publicKey, DEMO.usdcMint().publicKey)).toBe(12_500_000n);
  });

  it('denies unknown destinations', async () => {
    const { wall } = await setup();
    const r = await wall.transfer('research-agent', { asset: 'USDC', amount: '1', to: Keypair.generate().publicKey.toBase58() });
    expect(r.status).toBe('denied');
    expect(failed(r)).toEqual(['destination']);
  });

  it('denies global denylist hits even if an agent allows them', async () => {
    const { wall } = await setup((p) => p.agents['research-agent'].destinations.allow.push({ address: addr('knownDrainer'), label: 'oops' }));
    const r = await wall.transfer('research-agent', { asset: 'USDC', amount: '1', to: addr('knownDrainer') });
    expect(r.status).toBe('denied');
    expect(r.decision.reason).toContain('denylist');
  });

  it('escalates payments above the approval threshold, then executes on approval', async () => {
    const { wall } = await setup();
    const r = await wall.transfer('research-agent', { asset: 'USDC', amount: '150', to: addr('dataLabs') });
    expect(r.status).toBe('pending_approval');
    const approved = await wall.approve(r.id, 'tester');
    expect(approved.status).toBe('executed');
    expect(wall.spentLast24h('research-agent')).toBe(150);
  });

  it('rejected approvals never execute', async () => {
    const { wall } = await setup();
    const r = await wall.transfer('research-agent', { asset: 'USDC', amount: '150', to: addr('dataLabs') });
    expect(wall.reject(r.id, 'tester').status).toBe('rejected');
    await expect(wall.approve(r.id, 'tester')).rejects.toThrow(/not waiting/);
  });

  it('re-checks limits at approval time', async () => {
    const { wall } = await setup();
    const big = await wall.transfer('research-agent', { asset: 'USDC', amount: '200', to: addr('dataLabs') });
    for (let i = 0; i < 3; i++) await wall.approve((await wall.transfer('research-agent', { asset: 'USDC', amount: '150', to: addr('dataLabs') })).id, 't');
    // 450 spent, the 200 request would now exceed the 500 daily budget
    const r = await wall.approve(big.id, 'tester');
    expect(r.status).toBe('denied');
    expect(failed(r)).toContain('limit.daily');
  });

  it('enforces per-transaction and daily limits', async () => {
    const { wall } = await setup();
    expect(failed(await wall.transfer('research-agent', { asset: 'USDC', amount: '251', to: addr('acmeCloud') }))).toContain('limit.per_transaction');
    const { wall: w2 } = await setup((p) => (p.agents['research-agent'].approval.aboveUsd = undefined));
    await w2.transfer('research-agent', { asset: 'USDC', amount: '250', to: addr('acmeCloud') });
    await w2.transfer('research-agent', { asset: 'USDC', amount: '240', to: addr('acmeCloud') });
    const r = await w2.transfer('research-agent', { asset: 'USDC', amount: '20', to: addr('acmeCloud') });
    expect(failed(r)).toEqual(['limit.daily']);
  });

  it('rate limits runaway loops', async () => {
    const { wall } = await setup();
    const statuses = [];
    for (let i = 0; i < 7; i++) statuses.push((await wall.transfer('ops-agent', { asset: 'USDC', amount: '1', to: addr('acmeCloud') })).status);
    expect(statuses).toEqual(['executed', 'executed', 'executed', 'executed', 'executed', 'denied', 'denied']);
  });

  it('blocks frozen agents', async () => {
    const { wall } = await setup();
    wall.setAgentStatus('ops-agent', 'frozen', 'test');
    const r = await wall.transfer('ops-agent', { asset: 'USDC', amount: '1', to: addr('acmeCloud') });
    expect(r.decision.reason).toContain('frozen');
  });

  it('blocks assets the agent may not use', async () => {
    const { wall } = await setup();
    const r = await wall.transfer('research-agent', { asset: 'SOL', amount: '0.01', to: addr('acmeCloud') });
    expect(failed(r)).toEqual(['assets']);
  });

  it('blocks secrets in memos', async () => {
    const { wall } = await setup();
    const r = await wall.transfer('research-agent', { asset: 'USDC', amount: '1', to: addr('acmeCloud'), memo: 'pk sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz012345' });
    expect(failed(r)).toEqual(['dlp']);
  });

  it('sends IBANs to a human instead of blocking', async () => {
    const { wall } = await setup();
    const r = await wall.transfer('research-agent', { asset: 'USDC', amount: '1', to: addr('acmeCloud'), memo: 'refund to GE29NB0000000101904917' });
    expect(r.status).toBe('pending_approval');
  });

  it('refuses raw transactions with dangerous or foreign instructions', async () => {
    const { wall, ledger } = await setup();
    const { createApproveInstruction } = await import('@solana/spl-token');
    const wallet = DEMO.custody().publicKey;
    const tx = new Transaction().add(createApproveInstruction(getAssociatedTokenAddressSync(DEMO.usdcMint().publicKey, wallet), Keypair.generate().publicKey, wallet, 1n));
    tx.feePayer = wallet;
    tx.recentBlockhash = await ledger.latestBlockhash();
    const r = await wall.submitTransaction('research-agent', { transaction: tx.serialize({ requireAllSignatures: false }).toString('base64') });
    expect(r.status).toBe('denied');
    expect(failed(r)).toContain('instructions');
  });

  it('refuses transactions that need other signers', async () => {
    const { wall, ledger } = await setup();
    const other = Keypair.generate().publicKey;
    const tx = new Transaction().add(memoInstruction('hi', DEMO.custody().publicKey), memoInstruction('hi', other));
    tx.feePayer = DEMO.custody().publicKey;
    tx.recentBlockhash = await ledger.latestBlockhash();
    const r = await wall.submitTransaction('research-agent', { transaction: tx.serialize({ requireAllSignatures: false }).toString('base64') });
    expect(failed(r)).toContain('signers');
  });

  describe('x402', () => {
    const quote = (over: Partial<PaymentRequirements> = {}): PaymentRequirements => ({
      scheme: 'exact',
      network: 'solana-local',
      maxAmountRequired: '50000',
      resource: 'http://localhost:8787/demo/weather/forecast',
      payTo: addr('weatherMerchant'),
      asset: DEMO.usdcMint().publicKey.toBase58(),
      extra: { feePayer: addr('facilitator') },
      ...over,
    });
    const request = { url: 'http://localhost:8787/demo/weather/forecast?city=Tbilisi' };

    it('signs a valid quote for the facilitator to settle', async () => {
      const { wall } = await setup();
      const r = await wall.payX402('research-agent', { requirements: quote(), request });
      expect(r.status).toBe('signed');
      expect(r.xPayment).toBeTruthy();
      const payload = JSON.parse(Buffer.from(r.xPayment!, 'base64').toString());
      const tx = Transaction.from(Buffer.from(payload.payload.transaction, 'base64'));
      expect(tx.feePayer!.toBase58()).toBe(addr('facilitator'));
      expect(tx.signatures.find((s) => s.publicKey.equals(DEMO.custody().publicKey))?.signature).toBeTruthy();
    });

    it('rejects a quote that pays someone other than the pinned merchant wallet', async () => {
      const { wall } = await setup();
      const r = await wall.payX402('research-agent', { requirements: quote({ payTo: addr('attacker') }), request });
      expect(r.decision.reason).toContain('pinned');
    });

    it('rejects quotes above the price cap', async () => {
      const { wall } = await setup();
      const r = await wall.payX402('research-agent', { requirements: quote({ maxAmountRequired: '5000000' }), request });
      expect(r.decision.reason).toContain('above the $0.10 cap');
    });

    it('rejects merchants that are not approved', async () => {
      const { wall } = await setup();
      const r = await wall.payX402('research-agent', { requirements: quote({ resource: 'https://evil.example/x' }), request: { url: 'https://evil.example/x' } });
      expect(failed(r)).toContain('x402');
    });

    it('scans the outgoing request for leaks', async () => {
      const { wall } = await setup();
      const r = await wall.payX402('research-agent', {
        requirements: quote(),
        request: { ...request, headers: { authorization: 'Bearer sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz012345' } },
      });
      expect(failed(r)).toEqual(['dlp']);
    });
  });

  it('records everything in a verifiable audit log', async () => {
    const { wall } = await setup();
    await wall.transfer('research-agent', { asset: 'USDC', amount: '1', to: addr('acmeCloud') });
    await wall.transfer('research-agent', { asset: 'USDC', amount: '1', to: new PublicKey(addr('attacker')).toBase58() });
    const anchor = await wall.anchorAudit();
    expect(anchor.signature).toBeTruthy();
    expect(wall.audit.verify()).toMatchObject({ ok: true });
    expect(wall.audit.all().map((e) => e.type)).toEqual(['request.evaluated', 'request.executed', 'request.evaluated', 'audit.anchored']);
  });
});
