import { readFileSync } from 'node:fs';
import { timingSafeEqual } from 'node:crypto';
import express, { type NextFunction, type Request, type Response } from 'express';
import { z } from 'zod';
import { AgentWall, AgentWallError, type AgentRequest } from '../core/agentwall.js';

const dashboardHtml = readFileSync(new URL('./dashboard.html', import.meta.url), 'utf8');

export interface ServerOptions {
  wall: AgentWall;
  /** api key -> agent id */
  agentKeys: Map<string, string>;
  adminToken: string;
  /** Extra routers (e.g. the demo merchants) mounted before the 404 handler. */
  mount?: (app: express.Express) => void;
}

const TransferBody = z.object({
  asset: z.string().min(1),
  amount: z.union([z.string(), z.number()]),
  to: z.string().min(32),
  memo: z.string().max(566).optional(),
  purpose: z.string().max(500).optional(),
});

const RawTxBody = z.object({ transaction: z.string().min(1), purpose: z.string().max(500).optional() });

const X402Body = z.object({
  requirements: z.object({
    scheme: z.literal('exact'),
    network: z.string(),
    maxAmountRequired: z.string().regex(/^\d+$/),
    resource: z.string(),
    description: z.string().optional(),
    mimeType: z.string().optional(),
    payTo: z.string(),
    maxTimeoutSeconds: z.number().optional(),
    asset: z.string(),
    extra: z.record(z.string(), z.unknown()).optional(),
  }),
  request: z.object({
    url: z.string().url(),
    method: z.string().optional(),
    headers: z.record(z.string(), z.string()).optional(),
    body: z.string().optional(),
  }),
  purpose: z.string().max(500).optional(),
});

const SettlementBody = z.object({
  success: z.boolean(),
  transaction: z.string().optional(),
  network: z.string(),
  payer: z.string().optional(),
  errorReason: z.string().optional(),
});

function safeEqual(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

function bearer(req: Request): string | undefined {
  const h = req.header('authorization');
  return h?.startsWith('Bearer ') ? h.slice(7).trim() : undefined;
}

/** What admins see: everything except the signed payment payload. */
function adminView(r: AgentRequest) {
  const { xPayment: _omit, ...rest } = r;
  return rest;
}

type AsyncHandler = (req: Request, res: Response) => Promise<unknown> | unknown;
const h = (fn: AsyncHandler) => (req: Request, res: Response, next: NextFunction) => {
  Promise.resolve(fn(req, res)).catch(next);
};

export function createApp({ wall, agentKeys, adminToken, mount }: ServerOptions): express.Express {
  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: '256kb' }));

  const agentAuth = (req: Request, res: Response, next: NextFunction) => {
    const key = bearer(req);
    const agentId = key ? agentKeys.get(key) : undefined;
    if (!agentId) {
      res.status(401).json({ error: 'Missing or invalid agent API key' });
      return;
    }
    res.locals.agentId = agentId;
    next();
  };

  const adminAuth = (req: Request, res: Response, next: NextFunction) => {
    const token = bearer(req) ?? (typeof req.query.token === 'string' ? req.query.token : undefined);
    if (!token || !safeEqual(token, adminToken)) {
      res.status(401).json({ error: 'Missing or invalid admin token' });
      return;
    }
    next();
  };

  app.get('/health', (_req, res) => {
    res.json({ ok: true, network: wall.network, ledger: wall.ledger.kind, wallet: wall.wallet.toBase58() });
  });

  // ---- Agent API ------------------------------------------------------------
  const agent = express.Router();
  agent.use(agentAuth);

  agent.get('/me', (_req, res) => {
    res.json(wall.agentSummary(res.locals.agentId));
  });

  agent.post(
    '/transfers',
    h(async (req, res) => {
      const body = TransferBody.parse(req.body);
      res.status(201).json(await wall.transfer(res.locals.agentId, body));
    }),
  );

  agent.post(
    '/transactions',
    h(async (req, res) => {
      const body = RawTxBody.parse(req.body);
      res.status(201).json(await wall.submitTransaction(res.locals.agentId, body));
    }),
  );

  agent.post(
    '/x402/pay',
    h(async (req, res) => {
      const body = X402Body.parse(req.body);
      res.status(201).json(await wall.payX402(res.locals.agentId, body));
    }),
  );

  agent.get(
    '/requests/:id',
    h(async (req, res) => {
      const wait = Math.min(Number(req.query.wait ?? 0), 60) * 1000;
      res.json(await wall.waitFor(String(req.params.id), wait, res.locals.agentId));
    }),
  );

  agent.post(
    '/requests/:id/settlement',
    h(async (req, res) => {
      const body = SettlementBody.parse(req.body);
      res.json(adminView(wall.reportSettlement(res.locals.agentId, String(req.params.id), body)));
    }),
  );

  app.use('/v1', agent);

  // ---- Admin API (dashboard) -------------------------------------------------
  const admin = express.Router();
  admin.use(adminAuth);

  admin.get(
    '/state',
    h(async (_req, res) => {
      const snap = await wall.snapshot();
      res.json({ ...snap, requests: snap.requests.map(adminView) });
    }),
  );

  admin.get('/policy', (_req, res) => {
    res.json(wall.policy);
  });

  admin.get('/audit', (req, res) => {
    const limit = Math.min(Number(req.query.limit ?? 100), 1000);
    res.json({ entries: wall.audit.tail(limit).reverse(), verification: wall.audit.verify() });
  });

  admin.post(
    '/audit/anchor',
    h(async (_req, res) => {
      res.json(await wall.anchorAudit());
    }),
  );

  admin.post(
    '/approvals/:id/approve',
    h(async (req, res) => {
      const by = String(req.body?.by ?? 'admin');
      res.json(adminView(await wall.approve(String(req.params.id), by, req.body?.note)));
    }),
  );

  admin.post(
    '/approvals/:id/reject',
    h(async (req, res) => {
      const by = String(req.body?.by ?? 'admin');
      res.json(adminView(wall.reject(String(req.params.id), by, req.body?.note)));
    }),
  );

  admin.post('/agents/:id/freeze', (req, res) => {
    res.json(wall.setAgentStatus(String(req.params.id), 'frozen', String(req.body?.by ?? 'admin')));
  });

  admin.post('/agents/:id/unfreeze', (req, res) => {
    res.json(wall.setAgentStatus(String(req.params.id), 'active', String(req.body?.by ?? 'admin')));
  });

  admin.get('/events', (req, res) => {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
    });
    res.write(': connected\n\n');
    const send = (event: string, data: unknown) => res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
    const onRequest = (r: AgentRequest) => send('request', adminView(r));
    const onAudit = (e: unknown) => send('audit', e);
    const onAgents = (id: string) => send('agents', { id });
    wall.on('request', onRequest);
    wall.on('audit', onAudit);
    wall.on('agents', onAgents);
    const ping = setInterval(() => res.write(': ping\n\n'), 20_000);
    req.on('close', () => {
      clearInterval(ping);
      wall.off('request', onRequest);
      wall.off('audit', onAudit);
      wall.off('agents', onAgents);
    });
  });

  app.use('/admin', admin);

  // ---- Dashboard --------------------------------------------------------------
  app.get('/', (_req, res) => {
    res.type('html').send(dashboardHtml);
  });

  mount?.(app);

  app.use((_req, res) => {
    res.status(404).json({ error: 'Not found' });
  });

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    if (err instanceof z.ZodError) {
      res.status(400).json({ error: 'Invalid request body', issues: err.issues.map((i) => `${i.path.join('.')}: ${i.message}`) });
    } else if (err instanceof AgentWallError) {
      res.status(err.status).json({ error: err.message });
    } else if (err instanceof SyntaxError) {
      res.status(400).json({ error: 'Malformed JSON' });
    } else {
      console.error(err);
      res.status(500).json({ error: (err as Error)?.message ?? 'Internal error' });
    }
  });

  return app;
}
