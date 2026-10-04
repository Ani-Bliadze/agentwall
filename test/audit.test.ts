import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { AuditLog, readAuditFile, verifyEntries } from '../src/audit/log.js';

function tempLog() {
  const path = join(mkdtempSync(join(tmpdir(), 'agentwall-')), 'audit.jsonl');
  const log = new AuditLog(path);
  log.append('system.started', { network: 'solana-local' });
  log.append('request.evaluated', { outcome: 'allow', totalUsd: 12 }, { agentId: 'a', requestId: 'r1' });
  log.append('request.executed', { signature: 'abc', totalUsd: 12 }, { agentId: 'a', requestId: 'r1' });
  return { path, log };
}

describe('audit log', () => {
  it('builds a verifiable hash chain and survives a restart', () => {
    const { path, log } = tempLog();
    expect(log.verify()).toMatchObject({ ok: true, count: 3 });
    const reopened = new AuditLog(path);
    expect(reopened.head).toBe(log.head);
    reopened.append('agent.frozen', { by: 'admin' }, { agentId: 'a' });
    expect(reopened.verify()).toMatchObject({ ok: true, count: 4 });
  });

  it('detects an edited entry', () => {
    const { path } = tempLog();
    const lines = readFileSync(path, 'utf8').trim().split('\n');
    lines[1] = lines[1].replace('"totalUsd":12', '"totalUsd":1');
    writeFileSync(path, lines.join('\n') + '\n');
    const v = verifyEntries(readAuditFile(path));
    expect(v).toMatchObject({ ok: false, brokenAt: 2 });
    expect(() => new AuditLog(path)).toThrow(/Refusing to start/);
  });

  it('detects a deleted entry', () => {
    const { path } = tempLog();
    const lines = readFileSync(path, 'utf8').trim().split('\n');
    lines.splice(1, 1);
    writeFileSync(path, lines.join('\n') + '\n');
    expect(verifyEntries(readAuditFile(path)).ok).toBe(false);
  });
});
