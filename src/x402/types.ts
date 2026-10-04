/**
 * x402: HTTP 402 Payment Required, used for machine-to-machine payments.
 * A paid API answers 402 with the payment it wants; the client pays and
 * retries with an X-PAYMENT header. These types follow x402 v1 ("exact" scheme).
 */

export interface PaymentRequirements {
  scheme: 'exact';
  network: string;
  /** Price in the asset's base units (USDC has 6 decimals, so "50000" is $0.05). */
  maxAmountRequired: string;
  resource: string;
  description?: string;
  mimeType?: string;
  payTo: string;
  maxTimeoutSeconds?: number;
  /** Mint address of the token to pay with. */
  asset: string;
  extra?: { feePayer?: string; [key: string]: unknown };
}

export interface PaymentRequiredResponse {
  x402Version: 1;
  error?: string;
  accepts: PaymentRequirements[];
}

export interface PaymentPayload {
  x402Version: 1;
  scheme: 'exact';
  network: string;
  payload: { transaction: string };
}

export interface SettlementResponse {
  success: boolean;
  transaction?: string;
  network: string;
  payer?: string;
  errorReason?: string;
}

export const X_PAYMENT = 'X-PAYMENT';
export const X_PAYMENT_RESPONSE = 'X-PAYMENT-RESPONSE';

export function encodeHeader(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64');
}

export function decodeHeader<T>(value: string): T {
  return JSON.parse(Buffer.from(value, 'base64').toString('utf8')) as T;
}
