import { createHash } from 'node:crypto';
import { Keypair } from '@solana/web3.js';

/**
 * Deterministic keypairs for the local demo, so the demo policy file can name
 * fixed addresses. Anyone can derive these secrets: never fund them on mainnet.
 */
export function demoKeypair(name: string): Keypair {
  return Keypair.fromSeed(createHash('sha256').update(`agentwall-demo:${name}`).digest());
}

export const DEMO = {
  custody: () => demoKeypair('custody'),
  usdcMint: () => demoKeypair('usdc-mint'),
  mysteryMint: () => demoKeypair('mystery-token-mint'),
  mintAuthority: () => demoKeypair('mint-authority'),
  facilitator: () => demoKeypair('x402-facilitator'),
  weatherMerchant: () => demoKeypair('merchant:tbilisi-weather'),
  acmeCloud: () => demoKeypair('vendor:acme-cloud'),
  dataLabs: () => demoKeypair('vendor:datalabs'),
  gpuMarket: () => demoKeypair('merchant:gpu-spot-market'),
  attacker: () => demoKeypair('attacker'),
  knownDrainer: () => demoKeypair('known-drainer'),
};
