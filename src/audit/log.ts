import { createHash } from 'node:crypto';
import { appendFileSync, existsSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname } from 'node:path';

/**
 * Tamper-evident audit log.
 *
 * Every decision, approval and signature is appended as one JSON line. Each
 * entry stores the hash of the previous entry, so editing or deleting any past
 * line breaks the chain. The head hash can be anchored on Solana with a memo
 * transaction, which timestamps the whole history publicly.
 */

export type AuditType =
  | 'request.evaluated'
  | 'request.executed'
  | 'request.failed'
  | 'approval.requested'
  | 'approval.granted'
  | 'approval.rejected'
  | 'approval.expired'
  | 'x402.settled'
  | 'agent.frozen'
  | 'agent.unfrozen'
  | 'audit.anchored'
  | 'system.started';

export interface AuditEntry {
  seq: number;
  ts: string;
  type: AuditType;
  agentId?: string;
  requestId?: string;
  data: Record<string, unknown>;
  prevHash: string;
  hash: string;
}

export const GENESIS_HASH = '0'.repeat(64);

export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(value: unknown): unknown {
  if (typeof value === 'bigint') return value.toString();
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value as Record<string, unknown>)
        .sort()
        .filter((k) => (value as Record<string, unknown>)[k] !== undefined)
        .map((k) => [k, sortKeys((value as Record<string, unknown>)[k])]),
    );
  }
  return value;
}

export function hashEntry(entry: Omit<AuditEntry, 'hash'>): string {
  return createHash('sha256').update(entry.prevHash).update(canonicalJson({ ...entry, prevHash: undefined })).digest('hex');
}

export interface VerifyResult {
  ok: boolean;
  count: number;
  head: string;
  brokenAt?: number;
  error?: string;
}

export function verifyEntries(entries: AuditEntry[]): VerifyResult {
  let prev = GENESIS_HASH;
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    if (e.seq !== i + 1) return { ok: false, count: entries.length, head: prev, brokenAt: e.seq, error: `Sequence gap at line ${i + 1}` };
    if (e.prevHash !== prev) return { ok: false, count: entries.length, head: prev, brokenAt: e.seq, error: `Entry #${e.seq} does not link to the previous entry` };
    const { hash, ...rest } = e;
    if (hashEntry(rest) !== hash) return { ok: false, count: entries.length, head: prev, brokenAt: e.seq, error: `Entry #${e.seq} was modified` };
    prev = hash;
  }
  return { ok: true, count: entries.length, head: prev };
}

export function readAuditFile(path: string): AuditEntry[] {
  if (!existsSync(path)) return [];
  return readFileSync(path, 'utf8')
    .split('\n')
    .filter((l) => l.trim())
    .map((l) => JSON.parse(l) as AuditEntry);
}

export class AuditLog {
  private entries: AuditEntry[] = [];
  private listeners = new Set<(e: AuditEntry) => void>();

  /** @param path JSONL file to persist to. Omit for an in-memory log. */
  constructor(private readonly path?: string) {
    if (path) {
      mkdirSync(dirname(path), { recursive: true });
      this.entries = readAuditFile(path);
      const v = verifyEntries(this.entries);
      if (!v.ok) throw new Error(`Audit log ${path} failed verification: ${v.error}. Refusing to start.`);
    }
  }

  get head(): string {
    return this.entries.at(-1)?.hash ?? GENESIS_HASH;
  }

  get length(): number {
    return this.entries.length;
  }

  append(type: AuditType, data: Record<string, unknown>, meta: { agentId?: string; requestId?: string } = {}): AuditEntry {
    const base = {
      seq: this.entries.length + 1,
      ts: new Date().toISOString(),
      type,
      agentId: meta.agentId,
      requestId: meta.requestId,
      data: JSON.parse(canonicalJson(data)) as Record<string, unknown>,
      prevHash: this.head,
    };
    const entry: AuditEntry = { ...base, hash: hashEntry(base) };
    this.entries.push(entry);
    if (this.path) appendFileSync(this.path, JSON.stringify(entry) + '\n');
    for (const l of this.listeners) l(entry);
    return entry;
  }

  all(): readonly AuditEntry[] {
    return this.entries;
  }

  tail(n: number): AuditEntry[] {
    return this.entries.slice(-n);
  }

  verify(): VerifyResult {
    const fromDisk = this.path ? readAuditFile(this.path) : this.entries;
    return verifyEntries(fromDisk);
  }

  subscribe(listener: (e: AuditEntry) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }
}
