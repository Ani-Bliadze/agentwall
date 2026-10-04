import type { AgentRequest } from '../core/agentwall.js';
import {
  X_PAYMENT,
  X_PAYMENT_RESPONSE,
  decodeHeader,
  type PaymentRequiredResponse,
  type PaymentRequirements,
  type SettlementResponse,
} from '../x402/types.js';

/**
 * Client for AI agents. The agent never holds a private key: it asks
 * AgentWall to pay, and gets back either a receipt, a pending approval,
 * or a refusal with a reason it can act on.
 */

export class AgentWallDenied extends Error {
  constructor(readonly request: AgentRequest) {
    super(`AgentWall blocked this payment: ${request.decision.reason}`);
  }
}

export class AgentWallApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

export interface ClientOptions {
  baseUrl: string;
  apiKey: string;
  /** How long to wait for a human when a payment needs approval. Default 0 (return immediately). */
  approvalTimeoutMs?: number;
  /** Throw AgentWallDenied instead of returning denied requests. Default true. */
  throwOnDeny?: boolean;
  fetch?: typeof fetch;
}

export interface PaidResponse {
  response: Response;
  payment?: AgentRequest;
  settlement?: SettlementResponse;
}

const FINAL_BAD = new Set(['denied', 'rejected', 'expired', 'failed']);

export class AgentWallClient {
  private readonly f: typeof fetch;

  constructor(private readonly opts: ClientOptions) {
    this.f = opts.fetch ?? fetch;
  }

  private async call<T>(method: string, path: string, body?: unknown): Promise<T> {
    const res = await this.f(`${this.opts.baseUrl}${path}`, {
      method,
      headers: { authorization: `Bearer ${this.opts.apiKey}`, 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const json = (await res.json().catch(() => ({}))) as { error?: string; issues?: string[] };
    if (!res.ok) throw new AgentWallApiError(`${json.error ?? res.statusText}${json.issues ? `: ${json.issues.join('; ')}` : ''}`, res.status);
    return json as T;
  }

  private async settle(r: AgentRequest, waitMs = this.opts.approvalTimeoutMs ?? 0): Promise<AgentRequest> {
    let out = r;
    if (out.status === 'pending_approval' && waitMs > 0) {
      const deadline = Date.now() + waitMs;
      while (out.status === 'pending_approval' && Date.now() < deadline) {
        const wait = Math.min(30, Math.ceil((deadline - Date.now()) / 1000));
        out = await this.call<AgentRequest>('GET', `/v1/requests/${out.id}?wait=${wait}`);
      }
    }
    if ((this.opts.throwOnDeny ?? true) && FINAL_BAD.has(out.status)) throw new AgentWallDenied(out);
    return out;
  }

  /** Budget, limits and allowlists for this agent. Useful to put in an LLM's context. */
  me() {
    return this.call<Record<string, unknown>>('GET', '/v1/me');
  }

  async transfer(params: { asset: string; amount: string | number; to: string; memo?: string; purpose?: string }, opts: { approvalTimeoutMs?: number } = {}) {
    const r = await this.call<AgentRequest>('POST', '/v1/transfers', params);
    return this.settle(r, opts.approvalTimeoutMs);
  }

  /** Ask AgentWall to co-sign a transaction built elsewhere (base64, unsigned). */
  async submitTransaction(transaction: string, opts: { purpose?: string; approvalTimeoutMs?: number } = {}) {
    const r = await this.call<AgentRequest>('POST', '/v1/transactions', { transaction, purpose: opts.purpose });
    return this.settle(r, opts.approvalTimeoutMs);
  }

  getRequest(id: string, waitSeconds = 0) {
    return this.call<AgentRequest>('GET', `/v1/requests/${id}?wait=${waitSeconds}`);
  }

  /**
   * fetch() that can pay. If the server answers 402 Payment Required, AgentWall
   * checks the quote against policy, signs the payment, and the request is retried
   * with the X-PAYMENT header.
   */
  async fetch(url: string, init: RequestInit & { purpose?: string; approvalTimeoutMs?: number } = {}): Promise<PaidResponse> {
    const { purpose, approvalTimeoutMs, ...requestInit } = init;
    const first = await this.f(url, requestInit);
    if (first.status !== 402) return { response: first };

    const quote = (await first.json()) as PaymentRequiredResponse;
    const requirements: PaymentRequirements | undefined = quote.accepts?.find((a) => a.scheme === 'exact');
    if (!requirements) throw new AgentWallApiError('402 response has no supported payment option', 402);

    const headers: Record<string, string> = {};
    new Headers(requestInit.headers).forEach((v, k) => (headers[k] = v));
    const body = typeof requestInit.body === 'string' ? requestInit.body : undefined;

    let payment = await this.call<AgentRequest>('POST', '/v1/x402/pay', {
      requirements,
      request: { url, method: requestInit.method ?? 'GET', headers, body },
      purpose,
    });
    payment = await this.settle(payment, approvalTimeoutMs);
    if (payment.status !== 'signed' || !payment.xPayment) return { response: first, payment };

    const retryHeaders = new Headers(requestInit.headers);
    retryHeaders.set(X_PAYMENT, payment.xPayment);
    const response = await this.f(url, { ...requestInit, headers: retryHeaders });
    const header = response.headers.get(X_PAYMENT_RESPONSE);
    const settlement = header ? decodeHeader<SettlementResponse>(header) : undefined;
    if (settlement) {
      payment = await this.call<AgentRequest>('POST', `/v1/requests/${payment.id}/settlement`, settlement).catch(() => payment);
    }
    return { response, payment, settlement };
  }
}
