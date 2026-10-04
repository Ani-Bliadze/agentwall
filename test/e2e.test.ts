import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AgentWallClient, AgentWallDenied } from '../src/sdk/client.js';
import { startAgentWall } from '../src/server/bootstrap.js';
import { addr } from './helpers.js';

let litesvmAvailable = true;
try {
  await import('litesvm');
} catch {
  litesvmAvailable = false;
}

const ledgers = (['memory', 'litesvm'] as const).filter((l) => l === 'memory' || litesvmAvailable);

describe.each(ledgers)('HTTP API + SDK end to end (%s ledger)', (ledger) => {
  let wall: Awaited<ReturnType<typeof startAgentWall>>;
  let agent: AgentWallClient;
  const admin = (path: string, method = 'POST') =>
    fetch(`${wall.url}${path}`, { method, headers: { authorization: `Bearer ${wall.adminToken}`, 'content-type': 'application/json' }, body: method === 'POST' ? '{}' : undefined }).then((r) => r.json());

  beforeAll(async () => {
    wall = await startAgentWall({ demo: true, port: 0, quiet: true, ledger });
    agent = new AgentWallClient({ baseUrl: wall.url, apiKey: wall.agentKeys['research-agent'] });
  });
  afterAll(() => wall.close());

  it('rejects requests without a valid key', async () => {
    const bad = new AgentWallClient({ baseUrl: wall.url, apiKey: 'nope' });
    await expect(bad.me()).rejects.toThrow(/invalid agent API key/);
    expect((await fetch(`${wall.url}/admin/state`)).status).toBe(401);
  });

  it('executes an allowed transfer on the ledger', async () => {
    const r = await agent.transfer({ asset: 'USDC', amount: '2', to: addr('acmeCloud'), memo: 'INV-1' });
    expect(r.status).toBe('executed');
    expect(r.signature).toBeTruthy();
  });

  it('throws AgentWallDenied with the reason for blocked payments', async () => {
    const err = await agent.transfer({ asset: 'USDC', amount: '5', to: addr('attacker') }).catch((e) => e);
    expect(err).toBeInstanceOf(AgentWallDenied);
    expect(err.message).toContain('not on the allowlist');
  });

  it('pays an x402 API and the merchant settles on-chain', async () => {
    const { response, payment, settlement } = await agent.fetch(`${wall.url}/demo/weather/forecast?city=Tbilisi`);
    expect(response.status).toBe(200);
    expect(settlement?.success).toBe(true);
    expect(payment?.status).toBe('executed');
    expect(((await response.json()) as { city: string }).city).toBe('Tbilisi');
  });

  it('waits for a human approval and resumes', async () => {
    const waiting = new AgentWallClient({ baseUrl: wall.url, apiKey: wall.agentKeys['research-agent'], approvalTimeoutMs: 10_000 });
    const pending = waiting.transfer({ asset: 'USDC', amount: '120', to: addr('dataLabs') });
    let id: string | undefined;
    for (let i = 0; i < 50 && !id; i++) {
      await new Promise((r) => setTimeout(r, 50));
      const state = await admin('/admin/state', 'GET');
      id = state.requests.find((r: { status: string }) => r.status === 'pending_approval')?.id;
    }
    expect(id).toBeTruthy();
    await admin(`/admin/approvals/${id}/approve`);
    const done = await pending;
    expect(done.status).toBe('executed');
  });

  it('keeps an intact audit chain and anchors it', async () => {
    const anchor = await admin('/admin/audit/anchor');
    expect(anchor.signature).toBeTruthy();
    const audit = await admin('/admin/audit?limit=5', 'GET');
    expect(audit.verification.ok).toBe(true);
  });
});
