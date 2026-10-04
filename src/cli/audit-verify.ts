import { readAuditFile, verifyEntries } from '../audit/log.js';

const path = process.argv[2] ?? 'data/audit-solana-local.jsonl';
const entries = readAuditFile(path);
const v = verifyEntries(entries);

if (v.ok) {
  console.log(`✓ ${path}: ${v.count} entries, hash chain intact`);
  console.log(`  head ${v.head}`);
  const anchors = entries.filter((e) => e.type === 'audit.anchored');
  const last = anchors.at(-1);
  if (last) console.log(`  last anchored at #${last.data.seq} in Solana tx ${last.data.signature}`);
} else {
  console.error(`✕ ${path}: ${v.error} (entry #${v.brokenAt})`);
  process.exit(1);
}
