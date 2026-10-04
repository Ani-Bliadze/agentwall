/** Convert a human amount ("12.5") into base units (12_500_000n for 6 decimals). */
export function toBaseUnits(amount: string | number, decimals: number): bigint {
  const s = typeof amount === 'number' ? amount.toFixed(decimals) : amount.trim();
  if (!/^\d+(\.\d+)?$/.test(s)) throw new Error(`Invalid amount "${amount}"`);
  const [whole, frac = ''] = s.split('.');
  if (frac.length > decimals && /[1-9]/.test(frac.slice(decimals))) {
    throw new Error(`Amount "${amount}" has more than ${decimals} decimal places`);
  }
  return BigInt(whole) * 10n ** BigInt(decimals) + BigInt((frac + '0'.repeat(decimals)).slice(0, decimals) || '0');
}

/** Convert base units into a decimal string without losing precision. */
export function fromBaseUnits(amount: bigint, decimals: number): string {
  const neg = amount < 0n;
  const v = neg ? -amount : amount;
  const base = 10n ** BigInt(decimals);
  const whole = v / base;
  const frac = (v % base).toString().padStart(decimals, '0').replace(/0+$/, '');
  return `${neg ? '-' : ''}${whole}${frac ? '.' + frac : ''}`;
}

export function toNumber(amount: bigint, decimals: number): number {
  return Number(fromBaseUnits(amount, decimals));
}

export function usd(n: number): string {
  return `$${n.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: n < 1 ? 4 : 2 })}`;
}
