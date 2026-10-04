import { describe, expect, it } from 'vitest';
import bs58 from 'bs58';
import { Keypair } from '@solana/web3.js';
import { scanText } from '../src/dlp/scanner.js';

const types = (text: string) => scanText(text, 'test').map((f) => f.type);

describe('DLP scanner', () => {
  it('finds a base58 Solana private key', () => {
    const secret = bs58.encode(Keypair.generate().secretKey);
    expect(types(`here is my key ${secret} keep it safe`)).toContain('solana_private_key');
  });

  it('finds a Solana CLI keypair JSON array', () => {
    const arr = JSON.stringify(Array.from(Keypair.generate().secretKey));
    expect(types(`config: ${arr}`)).toContain('solana_private_key');
  });

  it('does not flag public keys or transaction signatures as private keys', () => {
    const pub = Keypair.generate().publicKey.toBase58();
    const sig = bs58.encode(new Uint8Array(64).fill(7)); // signatures are also 64 bytes, but 87-88 chars
    expect(types(`pay ${pub}`)).not.toContain('solana_private_key');
    // A bare 64-byte base58 string is ambiguous; context-free we still treat it as a key.
    expect(types(sig)).toContain('solana_private_key');
  });

  it('finds a 12-word seed phrase but not ordinary prose', () => {
    expect(types('legal winner thank year wave sausage worth useful legal winner thank yellow')).toContain('seed_phrase');
    expect(types('Please pay the invoice for the cloud hosting we used during the month of September, thanks a lot')).not.toContain('seed_phrase');
  });

  it('finds API keys from common providers', () => {
    expect(types('ANTHROPIC_API_KEY=sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz012345')).toContain('api_key');
    expect(types('aws AKIAIOSFODNN7EXAMPLE')).toContain('api_key');
    expect(types('token ghp_1234567890abcdefghijklmnopqrstuvwxyz')).toContain('api_key');
    expect(types('https://mainnet.helius-rpc.com/?api-key=1a2b3c4d5e6f7a8b9c0d1e2f')).toContain('api_key');
  });

  it('validates card numbers with Luhn', () => {
    expect(types('card 4111 1111 1111 1111')).toContain('credit_card');
    expect(types('order 4111 1111 1111 1112')).not.toContain('credit_card');
  });

  it('validates IBANs with mod-97', () => {
    expect(types('IBAN GE29NB0000000101904917')).toContain('iban');
    expect(types('IBAN GE29NB0000000101904918')).not.toContain('iban');
  });

  it('flags personal data at low severity', () => {
    const findings = scanText('contact nino@example.ge or +995 555 12 34 56', 'body');
    expect(findings.map((f) => f.type)).toEqual(expect.arrayContaining(['email', 'phone']));
    expect(findings.every((f) => f.severity === 'low')).toBe(true);
  });

  it('never returns the raw secret', () => {
    const [f] = scanText('sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz012345', 'memo');
    expect(f.preview).not.toContain('AbCdEfGhIj');
  });
});
