import { EventEmitter } from 'node:events';
import { randomBytes } from 'node:crypto';
import { Keypair, PublicKey, Transaction, VersionedTransaction } from '@solana/web3.js';
import type { AuditEntry, AuditLog } from '../audit/log.js';
import { scanText, type DlpPayload } from '../dlp/scanner.js';
import { evaluate, findMerchant, type Decision, type EvaluationInput, type RequestKind } from '../policy/engine.js';
import { assetByMint, assetBySymbol, type AgentPolicy, type PolicyFile } from '../policy/schema.js';
import { fromBaseUnits, toBaseUnits } from '../solana/amounts.js';
import { buildTransfer, memoInstruction } from '../solana/builder.js';
import { inspectTransaction, InspectionError } from '../solana/inspector.js';
import type { Ledger } from '../solana/ledger.js';
import type { Network } from '../solana/programs.js';
import { encodeHeader, type PaymentPayload, type PaymentRequirements, type SettlementResponse } from '../x402/types.js';

export type RequestStatus = 'executed' | 'signed' | 'denied' | 'pending_approval' | 'rejected' | 'expired' | 'failed';

export interface AgentRequest {
  id: string;
  agentId: string;
  kind: RequestKind;
  status: RequestStatus;
  createdAt: string;
  updatedAt: string;
  purpose?: string;
  decision: Decision;
  /** Solana transaction signature once executed. */
  signature?: string;
  /** For x402: the X-PAYMENT header value the agent attaches to its retry. */
  xPayment?: string;
  x402?: { url: string; merchant?: string; description?: string };
  approval?: { expiresAt: string; resolvedBy?: string; note?: string };
  error?: string;
}

export class AgentWallError extends Error {
  constructor(
    message: string,
    readonly status = 400,
  ) {
    super(message);
  }
}

export interface TransferParams {
  asset: string;
  amount: string | number;
  to: string;
  memo?: string;
  purpose?: string;
}

export interface X402Params {
  requirements: PaymentRequirements;
  request: { url: string; method?: string; headers?: Record<string, string>; body?: string };
  purpose?: string;
}

export interface AgentWallOptions {
  policy: PolicyFile;
  ledger: Ledger;
  custody: Keypair;
  network: Network;
  audit: AuditLog;
}

interface Pending {
  tx: Transaction | VersionedTransaction;
  input: EvaluationInput;
  timer: NodeJS.Timeout;
}

const DAY_MS = 24 * 60 * 60 * 1000;
const MINUTE_MS = 60 * 1000;
const IGNORED_HEADERS = new Set(['content-type', 'accept', 'user-agent', 'content-length', 'host', 'connection']);

/**
 * The AgentWall core: holds the wallet key, inspects every transaction an
 * agent asks for, runs the policy engine, and only signs what passes.
 */
export class AgentWall extends EventEmitter {
  readonly policy: PolicyFile;
  readonly ledger: Ledger;
  readonly network: Network;
  readonly audit: AuditLog;
  private readonly custody: Keypair;
  private requests = new Map<string, AgentRequest>();
  private pending = new Map<string, Pending>();
  private spend: { agentId: string; ts: number; usd: number }[] = [];
  private attempts: { agentId: string; ts: number }[] = [];
  private lastAnchor: { seq: number; head: string; signature: string; ts: string } | null = null;

  constructor(opts: AgentWallOptions) {
    super();
    this.policy = opts.policy;
    this.ledger = opts.ledger;
    this.network = opts.network;
    this.audit = opts.audit;
    this.custody = opts.custody;
    this.rebuildFromAudit();
    this.audit.subscribe((e) => this.emit('audit', e));
  }

  get wallet(): PublicKey {
    return this.custody.publicKey;
  }

  /** Spend counters are derived from the audit log, so restarts keep daily limits intact. */
  private rebuildFromAudit() {
    const cutoff = Date.now() - DAY_MS;
    for (const e of this.audit.all()) {
      const ts = Date.parse(e.ts);
      if ((e.type === 'request.executed') && ts > cutoff && e.agentId && typeof e.data.totalUsd === 'number') {
        this.spend.push({ agentId: e.agentId, ts, usd: e.data.totalUsd });
      }
      if (e.type === 'agent.frozen' && e.agentId && this.policy.agents[e.agentId]) this.policy.agents[e.agentId].status = 'frozen';
      if (e.type === 'agent.unfrozen' && e.agentId && this.policy.agents[e.agentId]) this.policy.agents[e.agentId].status = 'active';
      if (e.type === 'audit.anchored') this.lastAnchor = e.data as typeof this.lastAnchor;
    }
  }

  spentLast24h(agentId: string): number {
    const cutoff = Date.now() - DAY_MS;
    return this.spend.filter((s) => s.agentId === agentId && s.ts > cutoff).reduce((a, s) => a + s.usd, 0);
  }

  private attemptsLastMinute(agentId: string): number {
    const cutoff = Date.now() - MINUTE_MS;
    this.attempts = this.attempts.filter((a) => a.ts > cutoff);
    return this.attempts.filter((a) => a.agentId === agentId).length;
  }

  private agentPolicy(agentId: string): AgentPolicy {
    const p = this.policy.agents[agentId];
    if (!p) throw new AgentWallError(`Unknown agent "${agentId}"`, 403);
    return p;
  }

  // -------------------------------------------------------------------------
  // Agent-facing operations
  // -------------------------------------------------------------------------

  async transfer(agentId: string, params: TransferParams): Promise<AgentRequest> {
    this.agentPolicy(agentId);
    const asset = assetBySymbol(this.policy, this.network, params.asset);
    if (!asset) throw new AgentWallError(`Unknown asset "${params.asset}" on ${this.network}.`);
    let to: PublicKey;
    try {
      to = new PublicKey(params.to);
    } catch {
      throw new AgentWallError(`"${params.to}" is not a valid Solana address.`);
    }
    let amount: bigint;
    try {
      amount = toBaseUnits(String(params.amount), asset.decimals);
    } catch (e) {
      throw new AgentWallError((e as Error).message);
    }
    if (amount <= 0n) throw new AgentWallError('Amount must be positive.');
    const tx = await buildTransfer(this.ledger, {
      from: this.wallet,
      to,
      amount,
      mint: asset.mint ? new PublicKey(asset.mint) : null,
      decimals: asset.decimals,
      memo: params.memo,
    });
    return this.process(agentId, 'transfer', tx, { purpose: params.purpose });
  }

  async submitTransaction(agentId: string, params: { transaction: string; purpose?: string }): Promise<AgentRequest> {
    this.agentPolicy(agentId);
    let tx: Transaction | VersionedTransaction;
    try {
      const bytes = Buffer.from(params.transaction, 'base64');
      const vtx = VersionedTransaction.deserialize(bytes);
      tx = vtx.version === 'legacy' ? Transaction.from(bytes) : vtx;
    } catch {
      throw new AgentWallError('Could not deserialize the transaction. Send a base64-encoded Solana transaction.');
    }
    return this.process(agentId, 'raw', tx, { purpose: params.purpose });
  }

  async payX402(agentId: string, params: X402Params): Promise<AgentRequest> {
    const policy = this.agentPolicy(agentId);
    const req = params.requirements;
    if (req.scheme !== 'exact') throw new AgentWallError(`Unsupported x402 scheme "${req.scheme}".`);
    let payTo: PublicKey, mint: PublicKey;
    try {
      payTo = new PublicKey(req.payTo);
      mint = new PublicKey(req.asset);
    } catch {
      throw new AgentWallError('x402 requirements contain an invalid payTo or asset address.');
    }
    const asset = assetByMint(this.policy, this.network, req.asset);
    const decimals = asset?.decimals ?? Number(req.extra?.decimals ?? 6);
    const feePayer = req.extra?.feePayer ? new PublicKey(req.extra.feePayer) : this.wallet;
    const tx = await buildTransfer(this.ledger, {
      from: this.wallet,
      to: payTo,
      amount: BigInt(req.maxAmountRequired),
      mint,
      decimals,
      feePayer,
    });

    const url = new URL(params.request.url);
    const payloads: DlpPayload[] = [];
    if (url.search) payloads.push({ label: 'request URL query', text: decodeURIComponent(url.search) });
    if (params.request.body) payloads.push({ label: 'request body', text: params.request.body });
    for (const [k, v] of Object.entries(params.request.headers ?? {})) {
      if (!IGNORED_HEADERS.has(k.toLowerCase())) payloads.push({ label: `request header ${k}`, text: `${k}: ${v}` });
    }
    const merchant = findMerchant(policy, params.request.url);
    return this.process(agentId, 'x402', tx, {
      purpose: params.purpose,
      payloads,
      x402: { requestedUrl: params.request.url, requirements: req },
      // Query strings can carry secrets; only the origin and path are stored.
      meta: { url: `${url.origin}${url.pathname}`, merchant: merchant?.name, description: req.description },
    });
  }

  reportSettlement(agentId: string, id: string, settlement: SettlementResponse): AgentRequest {
    const r = this.getRequest(id, agentId);
    if (r.kind !== 'x402' || r.status !== 'signed') throw new AgentWallError('Only signed x402 payments can be settled.', 409);
    if (settlement.success && settlement.transaction) {
      r.signature = settlement.transaction;
      r.status = 'executed';
    } else {
      r.error = settlement.errorReason ?? 'Merchant reported a failed settlement';
    }
    this.audit.append('x402.settled', { ...settlement }, { agentId, requestId: id });
    return this.touch(r);
  }

  getRequest(id: string, agentId?: string): AgentRequest {
    const r = this.requests.get(id);
    if (!r || (agentId && r.agentId !== agentId)) throw new AgentWallError(`Request ${id} not found`, 404);
    return r;
  }

  /** Resolve once the request leaves pending_approval, or after the timeout. */
  waitFor(id: string, timeoutMs: number, agentId?: string): Promise<AgentRequest> {
    const r = this.getRequest(id, agentId);
    if (r.status !== 'pending_approval' || timeoutMs <= 0) return Promise.resolve(r);
    return new Promise((resolve) => {
      const onUpdate = (u: AgentRequest) => {
        if (u.id === id && u.status !== 'pending_approval') done();
      };
      const done = () => {
        clearTimeout(t);
        this.off('request', onUpdate);
        resolve(this.getRequest(id));
      };
      const t = setTimeout(done, timeoutMs);
      this.on('request', onUpdate);
    });
  }

  // -------------------------------------------------------------------------
  // The pipeline: inspect -> evaluate -> sign / escalate / deny
  // -------------------------------------------------------------------------

  private async process(
    agentId: string,
    kind: RequestKind,
    tx: Transaction | VersionedTransaction,
    opts: {
      purpose?: string;
      payloads?: DlpPayload[];
      x402?: EvaluationInput['x402'];
      meta?: AgentRequest['x402'];
    },
  ): Promise<AgentRequest> {
    let inspected;
    try {
      inspected = await inspectTransaction(tx, (a) => this.ledger.getTokenAccount(a));
    } catch (e) {
      if (e instanceof InspectionError) throw new AgentWallError(e.message);
      throw new AgentWallError(`Could not inspect transaction: ${(e as Error).message}`);
    }

    const input: EvaluationInput = {
      agentId,
      kind,
      network: this.network,
      custody: this.wallet.toBase58(),
      tx: inspected,
      payloads: opts.payloads ?? [],
      x402: opts.x402,
      spentLast24hUsd: this.spentLast24h(agentId),
      requestsLastMinute: this.attemptsLastMinute(agentId),
    };
    const decision = evaluate(this.policy, input);
    // The stated purpose is stored and shown in the console: never keep secrets in it.
    const purposeFindings = opts.purpose ? scanText(opts.purpose, 'purpose').filter((f) => f.severity !== 'low') : [];
    const purpose = purposeFindings.length ? `[redacted: contained ${[...new Set(purposeFindings.map((f) => f.type))].join(', ')}]` : opts.purpose;
    if (decision.transfers.some((t) => t.destinationOwner !== input.custody)) this.attempts.push({ agentId, ts: Date.now() });

    const now = new Date().toISOString();
    const request: AgentRequest = {
      id: `req_${randomBytes(6).toString('hex')}`,
      agentId,
      kind,
      status: 'denied',
      createdAt: now,
      updatedAt: now,
      purpose,
      decision,
      x402: opts.meta,
    };
    this.requests.set(request.id, request);
    this.trimHistory();

    this.audit.append(
      'request.evaluated',
      {
        kind,
        outcome: decision.outcome,
        reason: decision.reason,
        totalUsd: decision.totalUsd,
        purpose,
        transfers: decision.transfers,
        failedChecks: decision.checks.filter((c) => c.outcome !== 'pass'),
        x402: opts.meta,
      },
      { agentId, requestId: request.id },
    );

    if (decision.outcome === 'allow') {
      await this.execute(request, tx);
    } else if (decision.outcome === 'require_approval') {
      const timeoutSec = this.policy.agents[agentId]?.approval.timeoutSeconds ?? 900;
      request.status = 'pending_approval';
      request.approval = { expiresAt: new Date(Date.now() + timeoutSec * 1000).toISOString() };
      const timer = setTimeout(() => this.expire(request.id), timeoutSec * 1000);
      timer.unref();
      this.pending.set(request.id, { tx, input, timer });
      this.audit.append('approval.requested', { reason: decision.reason, totalUsd: decision.totalUsd }, { agentId, requestId: request.id });
    }
    return this.touch(request);
  }

  private async execute(request: AgentRequest, tx: Transaction | VersionedTransaction) {
    try {
      // Refresh the blockhash: approvals can take minutes and blockhashes expire.
      // Safe because AgentWall is the only signer that has signed so far.
      const blockhash = await this.ledger.latestBlockhash();
      if (tx instanceof Transaction) {
        tx.recentBlockhash = blockhash;
        tx.signatures.forEach((s) => (s.signature = null));
        tx.partialSign(this.custody);
      } else {
        tx.message.recentBlockhash = blockhash;
        tx.signatures = tx.signatures.map(() => new Uint8Array(64));
        tx.sign([this.custody]);
      }

      if (request.kind === 'x402') {
        // The merchant's facilitator adds its fee-payer signature and settles.
        const serialized = tx instanceof Transaction ? tx.serialize({ requireAllSignatures: false }) : tx.serialize();
        const payload: PaymentPayload = {
          x402Version: 1,
          scheme: 'exact',
          network: this.network,
          payload: { transaction: Buffer.from(serialized).toString('base64') },
        };
        request.xPayment = encodeHeader(payload);
        request.status = 'signed';
      } else {
        request.signature = await this.ledger.sendTransaction(tx);
        request.status = 'executed';
      }
      this.spend.push({ agentId: request.agentId, ts: Date.now(), usd: request.decision.totalUsd });
      this.audit.append(
        'request.executed',
        { kind: request.kind, totalUsd: request.decision.totalUsd, signature: request.signature, mode: request.kind === 'x402' ? 'signed-for-facilitator' : 'submitted' },
        { agentId: request.agentId, requestId: request.id },
      );
    } catch (e) {
      request.status = 'failed';
      request.error = (e as Error).message;
      this.audit.append('request.failed', { error: request.error }, { agentId: request.agentId, requestId: request.id });
    }
  }

  // -------------------------------------------------------------------------
  // Human-in-the-loop
  // -------------------------------------------------------------------------

  async approve(id: string, by: string, note?: string): Promise<AgentRequest> {
    const request = this.getRequest(id);
    const p = this.pending.get(id);
    if (!p || request.status !== 'pending_approval') throw new AgentWallError(`Request ${id} is not waiting for approval.`, 409);
    clearTimeout(p.timer);
    this.pending.delete(id);
    request.approval = { ...request.approval!, resolvedBy: by, note };

    // Re-check everything except the approval rules: limits or agent status may have changed.
    const recheck = evaluate(this.policy, {
      ...p.input,
      spentLast24hUsd: this.spentLast24h(request.agentId),
      requestsLastMinute: 0,
      humanApproved: true,
    });
    this.audit.append('approval.granted', { by, note, recheck: recheck.outcome, reason: recheck.reason }, { agentId: request.agentId, requestId: id });
    if (recheck.outcome !== 'allow') {
      request.status = 'denied';
      request.decision = recheck;
      return this.touch(request);
    }
    request.decision = { ...recheck, reason: `Approved by ${by}. ${recheck.reason}` };
    await this.execute(request, p.tx);
    return this.touch(request);
  }

  reject(id: string, by: string, note?: string): AgentRequest {
    const request = this.getRequest(id);
    const p = this.pending.get(id);
    if (!p || request.status !== 'pending_approval') throw new AgentWallError(`Request ${id} is not waiting for approval.`, 409);
    clearTimeout(p.timer);
    this.pending.delete(id);
    request.status = 'rejected';
    request.approval = { ...request.approval!, resolvedBy: by, note };
    request.decision = { ...request.decision, reason: `Rejected by ${by}${note ? `: ${note}` : '.'}` };
    this.audit.append('approval.rejected', { by, note }, { agentId: request.agentId, requestId: id });
    return this.touch(request);
  }

  private expire(id: string) {
    const request = this.requests.get(id);
    if (!request || request.status !== 'pending_approval') return;
    this.pending.delete(id);
    request.status = 'expired';
    request.decision = { ...request.decision, reason: 'Approval request expired without a decision.' };
    this.audit.append('approval.expired', {}, { agentId: request.agentId, requestId: id });
    this.touch(request);
  }

  setAgentStatus(agentId: string, status: 'active' | 'frozen', by: string): AgentPolicy {
    const p = this.agentPolicy(agentId);
    if (p.status === status) return p;
    p.status = status;
    this.audit.append(status === 'frozen' ? 'agent.frozen' : 'agent.unfrozen', { by }, { agentId });
    this.emit('agents', agentId);
    return p;
  }

  // -------------------------------------------------------------------------
  // Audit anchoring
  // -------------------------------------------------------------------------

  /** Write the audit chain head to Solana in a memo, timestamping the full history. */
  async anchorAudit(): Promise<{ seq: number; head: string; signature: string }> {
    const seq = this.audit.length;
    const head = this.audit.head;
    const tx = new Transaction().add(memoInstruction(`agentwall:audit:v1:${seq}:${head}`, this.wallet));
    tx.feePayer = this.wallet;
    tx.recentBlockhash = await this.ledger.latestBlockhash();
    tx.sign(this.custody);
    const signature = await this.ledger.sendTransaction(tx);
    this.lastAnchor = { seq, head, signature, ts: new Date().toISOString() };
    this.audit.append('audit.anchored', this.lastAnchor);
    return this.lastAnchor;
  }

  // -------------------------------------------------------------------------
  // Views
  // -------------------------------------------------------------------------

  async balances(): Promise<{ asset: string; amount: string; usd: number }[]> {
    const out: { asset: string; amount: string; usd: number }[] = [];
    for (const [symbol, a] of Object.entries(this.policy.assets)) {
      if (a.native) {
        const v = await this.ledger.getSolBalance(this.wallet);
        out.push({ asset: symbol, amount: fromBaseUnits(v, a.decimals), usd: Number(fromBaseUnits(v, a.decimals)) * a.usdPrice });
      } else if (a.mints[this.network]) {
        const v = await this.ledger.getTokenBalance(this.wallet, new PublicKey(a.mints[this.network]!));
        out.push({ asset: symbol, amount: fromBaseUnits(v, a.decimals), usd: Number(fromBaseUnits(v, a.decimals)) * a.usdPrice });
      }
    }
    return out;
  }

  agentSummary(agentId: string) {
    const p = this.agentPolicy(agentId);
    const spent = this.spentLast24h(agentId);
    return {
      id: agentId,
      description: p.description,
      status: p.status,
      limits: p.limits,
      approvalAboveUsd: p.approval.aboveUsd ?? null,
      spentLast24hUsd: spent,
      remainingTodayUsd: Math.max(0, p.limits.dailyUsd - spent),
      assets: p.assets,
      destinations: p.destinations.allow.map((d) => ({ label: d.label, address: d.address })),
      merchants: p.x402.merchants.map((m) => ({ name: m.name, urlPrefix: m.urlPrefix, maxPriceUsd: m.maxPriceUsd ?? p.x402.maxPriceUsd })),
    };
  }

  listRequests(limit = 100): AgentRequest[] {
    return [...this.requests.values()].slice(-limit).reverse();
  }

  async snapshot() {
    const requests = [...this.requests.values()];
    const count = (s: RequestStatus[]) => requests.filter((r) => s.includes(r.status)).length;
    return {
      network: this.network,
      ledger: this.ledger.kind,
      wallet: this.wallet.toBase58(),
      balances: await this.balances(),
      agents: Object.keys(this.policy.agents).map((id) => this.agentSummary(id)),
      stats: {
        total: requests.length,
        allowed: count(['executed', 'signed']),
        blocked: count(['denied', 'rejected', 'expired']),
        pending: count(['pending_approval']),
        failed: count(['failed']),
        spentLast24hUsd: Object.keys(this.policy.agents).reduce((s, id) => s + this.spentLast24h(id), 0),
      },
      requests: this.listRequests(100),
      audit: { length: this.audit.length, head: this.audit.head, lastAnchor: this.lastAnchor, verification: this.audit.verify() },
    };
  }

  private touch(r: AgentRequest): AgentRequest {
    r.updatedAt = new Date().toISOString();
    this.emit('request', r);
    return r;
  }

  private trimHistory() {
    if (this.requests.size <= 1000) return;
    for (const [id, r] of this.requests) {
      if (this.requests.size <= 1000) break;
      if (r.status !== 'pending_approval') this.requests.delete(id);
    }
  }
}

export type { AuditEntry };
