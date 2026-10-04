import bs58 from 'bs58';
import { BIP39_ENGLISH } from './bip39-english.js';

/**
 * Data-loss prevention scanner.
 *
 * Agents leak data in places people forget to look: payment memos (which are
 * public on-chain forever), query strings and bodies sent to paid APIs, and
 * request headers. Every outbound payload goes through this scanner before
 * AgentWall signs anything.
 */

export const DLP_TYPES = [
  'solana_private_key',
  'seed_phrase',
  'evm_private_key',
  'api_key',
  'jwt',
  'password',
  'credit_card',
  'iban',
  'email',
  'phone',
] as const;

export type DlpType = (typeof DLP_TYPES)[number];
export type DlpSeverity = 'critical' | 'high' | 'medium' | 'low';

export interface DlpFinding {
  type: DlpType;
  severity: DlpSeverity;
  /** Which payload the finding came from, e.g. "memo" or "request.body". */
  location: string;
  /** Masked preview, never the raw secret. */
  preview: string;
  detail?: string;
}

export interface DlpPayload {
  label: string;
  text: string;
}

const SEVERITY: Record<DlpType, DlpSeverity> = {
  solana_private_key: 'critical',
  seed_phrase: 'critical',
  evm_private_key: 'critical',
  api_key: 'critical',
  jwt: 'high',
  password: 'high',
  credit_card: 'high',
  iban: 'medium',
  email: 'low',
  phone: 'low',
};

export function mask(value: string): string {
  const v = value.trim();
  if (v.length <= 8) return '*'.repeat(v.length);
  return `${v.slice(0, 4)}${'*'.repeat(Math.min(12, v.length - 8))}${v.slice(-4)}`;
}

// ---------------------------------------------------------------------------
// Individual detectors
// ---------------------------------------------------------------------------

const BASE58_RUN = /[1-9A-HJ-NP-Za-km-z]{80,90}/g;

function detectSolanaPrivateKeys(text: string): string[] {
  const hits: string[] = [];
  for (const m of text.matchAll(BASE58_RUN)) {
    try {
      const bytes = bs58.decode(m[0]);
      if (bytes.length === 64) hits.push(m[0]);
    } catch {
      /* not base58 */
    }
  }
  // Solana CLI keypair file format: a JSON array of 64 bytes.
  for (const m of text.matchAll(/\[\s*(\d{1,3}\s*,\s*){63}\d{1,3}\s*\]/g)) {
    const nums = m[0]
      .replace(/[[\]\s]/g, '')
      .split(',')
      .map(Number);
    if (nums.length === 64 && nums.every((n) => n >= 0 && n <= 255)) hits.push(m[0]);
  }
  return hits;
}

const VALID_MNEMONIC_LENGTHS = new Set([12, 15, 18, 21, 24]);

function detectSeedPhrases(text: string): string[] {
  const tokens = text.toLowerCase().split(/[^a-z]+/).filter(Boolean);
  const hits: string[] = [];
  let run: string[] = [];
  const flush = () => {
    if (run.length >= 12) {
      // Any 12+ run of BIP-39 words is suspicious; exact lengths are near certain.
      const len = [...VALID_MNEMONIC_LENGTHS].reverse().find((l) => run.length >= l) ?? 12;
      hits.push(run.slice(0, len).join(' '));
    }
    run = [];
  };
  for (const t of tokens) {
    if (BIP39_ENGLISH.has(t)) run.push(t);
    else flush();
  }
  flush();
  return hits;
}

const EVM_KEY_CONTEXT = /(priv(ate)?[\s_-]*key|secret|mnemonic|pk|signer)\W{0,20}(0x)?([a-f0-9]{64})\b/gi;

function detectEvmPrivateKeys(text: string): string[] {
  return [...text.matchAll(EVM_KEY_CONTEXT)].map((m) => m[4]);
}

const API_KEY_PATTERNS: { name: string; re: RegExp }[] = [
  { name: 'Anthropic', re: /\bsk-ant-[A-Za-z0-9_-]{20,}/g },
  { name: 'OpenAI', re: /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}/g },
  { name: 'AWS access key', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { name: 'GitHub', re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}/g },
  { name: 'Slack', re: /\bxox[abprs]-[A-Za-z0-9-]{10,}/g },
  { name: 'Google', re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { name: 'Stripe', re: /\b(?:sk|rk)_live_[0-9A-Za-z]{20,}/g },
  { name: 'Helius/RPC key in URL', re: /[?&](?:api[-_]?key|apikey|token)=[A-Za-z0-9_-]{20,}/gi },
  { name: 'Bearer token', re: /\bBearer\s+[A-Za-z0-9._~+/-]{24,}=*/g },
];

function detectApiKeys(text: string): { value: string; detail: string }[] {
  const out: { value: string; detail: string }[] = [];
  for (const { name, re } of API_KEY_PATTERNS) {
    for (const m of text.matchAll(re)) out.push({ value: m[0], detail: name });
  }
  // "Bearer <key>" and "?api_key=<key>" wrap keys a specific pattern may already have found.
  return out.filter((f, i) => !out.some((g, j) => j !== i && f.value !== g.value && f.value.includes(g.value)));
}

const JWT = /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g;
const PASSWORD = /\b(?:password|passwd|pwd|passphrase)\s*[:=]\s*["']?([^\s"',;]{4,})/gi;

function luhnValid(digits: string): boolean {
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

function detectCards(text: string): string[] {
  const hits: string[] = [];
  for (const m of text.matchAll(/\b(?:\d[ -]?){12,18}\d\b/g)) {
    const digits = m[0].replace(/[ -]/g, '');
    if (digits.length < 13 || digits.length > 19) continue;
    if (/^(\d)\1+$/.test(digits)) continue;
    if (!/^(?:4|5[1-5]|2[2-7]|3[47]|6(?:011|5)|35)/.test(digits)) continue;
    if (luhnValid(digits)) hits.push(m[0]);
  }
  return hits;
}

function ibanValid(iban: string): boolean {
  const s = iban.replace(/\s+/g, '').toUpperCase();
  if (s.length < 15 || s.length > 34) return false;
  const rearranged = s.slice(4) + s.slice(0, 4);
  let rem = 0;
  for (const ch of rearranged) {
    const code = ch.charCodeAt(0);
    const val = code >= 65 ? String(code - 55) : ch;
    for (const digit of val) rem = (rem * 10 + Number(digit)) % 97;
  }
  return rem === 1;
}

function detectIbans(text: string): string[] {
  const hits: string[] = [];
  for (const m of text.matchAll(/\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{2,4}){3,8}\b/g)) {
    if (ibanValid(m[0])) hits.push(m[0]);
  }
  return hits;
}

const EMAIL = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
const PHONE = /(?<![\w/])\+\d{1,3}[\s-]?\(?\d{2,4}\)?(?:[\s-]?\d{2,4}){2,4}\b/g;

// ---------------------------------------------------------------------------

export function scanText(text: string, location: string): DlpFinding[] {
  const findings: DlpFinding[] = [];
  const add = (type: DlpType, value: string, detail?: string) =>
    findings.push({ type, severity: SEVERITY[type], location, preview: mask(value), detail });

  const solKeys = detectSolanaPrivateKeys(text);
  solKeys.forEach((v) => add('solana_private_key', v));
  detectSeedPhrases(text).forEach((v) => add('seed_phrase', v, `${v.split(' ').length} BIP-39 words`));
  detectEvmPrivateKeys(text).forEach((v) => add('evm_private_key', v));
  detectApiKeys(text).forEach(({ value, detail }) => add('api_key', value, detail));
  for (const m of text.matchAll(JWT)) add('jwt', m[0]);
  for (const m of text.matchAll(PASSWORD)) add('password', m[1]);
  detectCards(text).forEach((v) => add('credit_card', v));
  detectIbans(text).forEach((v) => add('iban', v));
  for (const m of text.matchAll(EMAIL)) add('email', m[0]);
  for (const m of text.matchAll(PHONE)) add('phone', m[0]);

  return dedupe(findings);
}

export function scanPayloads(payloads: DlpPayload[]): DlpFinding[] {
  return payloads.flatMap((p) => scanText(p.text, p.label));
}

function dedupe(findings: DlpFinding[]): DlpFinding[] {
  const seen = new Set<string>();
  return findings.filter((f) => {
    const key = `${f.type}|${f.location}|${f.preview}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
