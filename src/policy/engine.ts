import { getAssociatedTokenAddressSync } from '@solana/spl-token';
import { PublicKey } from '@solana/web3.js';
import { scanPayloads, type DlpFinding, type DlpPayload } from '../dlp/scanner.js';
import { fromBaseUnits, toNumber, usd } from '../solana/amounts.js';
import { shortAddress, type InspectedTransaction } from '../solana/inspector.js';
import { KNOWN_PROGRAMS, type Network } from '../solana/programs.js';
import type { PaymentRequirements } from '../x402/types.js';
import { assetByMint, type AgentPolicy, type Merchant, type PolicyFile } from './schema.js';

export type RequestKind = 'transfer' | 'x402' | 'raw';
export type CheckOutcome = 'pass' | 'warn' | 'deny' | 'require_approval';
export type DecisionOutcome = 'allow' | 'deny' | 'require_approval';

export interface CheckResult {
  rule: string;
  outcome: CheckOutcome;
  message: string;
}

export interface PricedTransfer {
  index: number;
  asset: string | null;
  mint: string | null;
  amountBase: string;
  amount: string;
  usd: number | null;
  destinationOwner: string | null;
  destinationLabel: string;
}

export interface Decision {
  outcome: DecisionOutcome;
  /** One-line explanation, written to be fed straight back to an LLM agent. */
  reason: string;
  totalUsd: number;
  transfers: PricedTransfer[];
  /** Every instruction in the transaction, as program.instruction. */
  instructions: string[];
  checks: CheckResult[];
  dlpFindings: DlpFinding[];
}

export interface X402Context {
  /** URL the agent actually requested. */
  requestedUrl: string;
  requirements: PaymentRequirements;
}

export interface EvaluationInput {
  agentId: string;
  kind: RequestKind;
  network: Network;
  custody: string;
  tx: InspectedTransaction;
  /** Outbound data that leaves the system with this request (memos are added automatically). */
  payloads?: DlpPayload[];
  x402?: X402Context;
  spentLast24hUsd: number;
  requestsLastMinute: number;
  /** Set when re-checking a request a human already approved. */
  humanApproved?: boolean;
}

export function findMerchant(agent: AgentPolicy, url: string): Merchant | undefined {
  return agent.x402.merchants
    .filter((m) => url.startsWith(m.urlPrefix))
    .sort((a, b) => b.urlPrefix.length - a.urlPrefix.length)[0];
}

export function evaluate(policy: PolicyFile, input: EvaluationInput): Decision {
  const checks: CheckResult[] = [];
  const add = (rule: string, outcome: CheckOutcome, message: string) => checks.push({ rule, outcome, message });
  const agent = policy.agents[input.agentId];
  const { tx, custody } = input;

  // ---- Price every transfer ------------------------------------------------
  const transfers: PricedTransfer[] = tx.transfers.map((t) => {
    const asset = t.kind === 'sol' ? assetByMint(policy, input.network, null) : t.mint ? assetByMint(policy, input.network, t.mint) : null;
    const decimals = asset?.decimals ?? t.decimals ?? 0;
    const amountNum = toNumber(t.amount, decimals);
    return {
      index: t.index,
      asset: asset?.symbol ?? null,
      mint: t.kind === 'sol' ? null : t.mint ?? null,
      amountBase: t.amount.toString(),
      amount: fromBaseUnits(t.amount, decimals),
      usd: asset ? amountNum * asset.usdPrice : null,
      destinationOwner: t.destinationOwner,
      destinationLabel: labelFor(policy, agent, t.destinationOwner, custody),
    };
  });
  const outgoing = transfers.filter((t) => t.destinationOwner !== custody);
  const totalUsd = outgoing.reduce((sum, t) => sum + (t.usd ?? 0), 0);
  const dlpFindings = scanPayloads([
    ...tx.memos.map((m, i) => ({ label: tx.memos.length > 1 ? `memo #${i + 1} (public on-chain)` : 'memo (public on-chain)', text: m })),
    ...(input.payloads ?? []),
  ]);

  const finish = (): Decision => {
    const deny = checks.filter((c) => c.outcome === 'deny');
    const approve = checks.filter((c) => c.outcome === 'require_approval');
    const outcome: DecisionOutcome = deny.length ? 'deny' : approve.length ? 'require_approval' : 'allow';
    const reason =
      outcome === 'deny'
        ? deny.map((c) => c.message).join(' ')
        : outcome === 'require_approval'
          ? `Needs human approval: ${approve.map((c) => c.message).join(' ')}`
          : `Allowed: ${outgoing.length ? outgoing.map((t) => `${t.amount} ${t.asset ?? '?'} to ${t.destinationLabel}`).join(', ') : 'no funds leave the wallet'}.`;
    return { outcome, reason, totalUsd, transfers, instructions: tx.instructions.map((i) => `${i.program === i.programId ? shortAddress(i.programId) : i.program}.${i.name}`), checks, dlpFindings };
  };

  // ---- 1. Agent status -----------------------------------------------------
  if (!agent) {
    add('agent', 'deny', `Unknown agent "${input.agentId}".`);
    return finish();
  }
  if (agent.status === 'frozen') {
    add('agent', 'deny', `Agent "${input.agentId}" is frozen. All spending is paused.`);
    return finish();
  }
  add('agent', 'pass', `Agent "${input.agentId}" is active.`);

  // ---- 2. Signers & fee payer ---------------------------------------------
  const facilitator = input.kind === 'x402' ? input.x402?.requirements.extra?.feePayer : undefined;
  const allowedSigners = new Set([custody, ...(facilitator ? [facilitator] : [])]);
  const foreignSigners = tx.signers.filter((s) => !allowedSigners.has(s));
  if (!tx.signers.includes(custody)) {
    add('signers', 'deny', 'The transaction does not require the AgentWall wallet to sign.');
  } else if (foreignSigners.length) {
    add('signers', 'deny', `The transaction requires unexpected co-signers: ${foreignSigners.map(shortAddress).join(', ')}.`);
  } else if (!allowedSigners.has(tx.feePayer)) {
    add('signers', 'deny', `Unexpected fee payer ${shortAddress(tx.feePayer)}.`);
  } else {
    add('signers', 'pass', facilitator ? 'Signed by AgentWall, fees paid by the x402 facilitator.' : 'Only the AgentWall wallet signs.');
  }

  // ---- 3. Instructions & programs -----------------------------------------
  const allowedPrograms = new Set(
    agent.programs.map((p) => (p in KNOWN_PROGRAMS ? KNOWN_PROGRAMS[p as keyof typeof KNOWN_PROGRAMS].toBase58() : p)),
  );
  let instructionProblems = 0;
  for (const ix of tx.instructions) {
    if (ix.risk === 'dangerous') {
      add('instructions', 'deny', `Instruction #${ix.index} (${ix.program}.${ix.name}) is blocked: ${ix.note}`);
      instructionProblems++;
    } else if (!allowedPrograms.has(ix.programId)) {
      add('instructions', 'deny', `Program ${ix.program === ix.programId ? shortAddress(ix.programId) : ix.program} is not on this agent's program allowlist.`);
      instructionProblems++;
    } else if (ix.risk === 'unsupported') {
      add('instructions', 'deny', `Instruction #${ix.index} (${ix.program}.${ix.name}) is not supported for agents.`);
      instructionProblems++;
    } else if (ix.risk === 'unknown_program') {
      add('instructions', 'warn', `Program ${shortAddress(ix.programId)} is allowlisted but cannot be decoded; its effects are not checked.`);
    }
  }
  if (!instructionProblems) add('instructions', 'pass', `${tx.instructions.length} instruction(s), all on the allowlist.`);

  // ---- 4. Authority over moved funds --------------------------------------
  const foreignAuthority = tx.transfers.filter((t) => t.authority !== custody);
  if (foreignAuthority.length) {
    add('authority', 'deny', 'The transaction moves funds that are not controlled by the AgentWall wallet.');
  }

  // ---- 5. Assets -----------------------------------------------------------
  const badAssets = outgoing.filter((t) => !t.asset || !agent.assets.includes(t.asset));
  if (badAssets.length) {
    for (const t of badAssets) {
      add('assets', 'deny', t.asset ? `Asset ${t.asset} is not allowed for this agent (allowed: ${agent.assets.join(', ')}).` : `Unknown token mint ${shortAddress(t.mint)}. Only ${agent.assets.join(', ')} can be sent.`);
    }
  } else if (outgoing.length) {
    add('assets', 'pass', `Assets allowed (${[...new Set(outgoing.map((t) => t.asset))].join(', ')}).`);
  }

  const merchant = input.x402 ? findMerchant(agent, input.x402.requestedUrl) : undefined;

  // ---- 6. x402 quote -------------------------------------------------------------
  if (input.kind === 'x402' && input.x402) {
    const { requirements: req, requestedUrl } = input.x402;
    if (!agent.x402.enabled) add('x402', 'deny', 'x402 payments are disabled for this agent.');
    else if (!merchant) add('x402', 'deny', `${new URL(requestedUrl).origin}${new URL(requestedUrl).pathname} is not an approved x402 merchant.`);
    else {
      const problems: string[] = [];
      if (req.network !== input.network) problems.push(`quote is for network ${req.network}, AgentWall runs on ${input.network}`);
      if (!req.resource.startsWith(merchant.urlPrefix)) problems.push(`quote is for a different resource (${req.resource})`);
      if (merchant.payTo && merchant.payTo !== req.payTo) problems.push(`quote asks to pay ${shortAddress(req.payTo)}, but ${merchant.name} is pinned to ${shortAddress(merchant.payTo)} (possible compromised merchant)`);
      const asset = assetByMint(policy, input.network, req.asset);
      const priceUsd = asset ? toNumber(BigInt(req.maxAmountRequired), asset.decimals) * asset.usdPrice : Infinity;
      const cap = merchant.maxPriceUsd ?? agent.x402.maxPriceUsd;
      if (priceUsd > cap) problems.push(`price ${asset ? usd(priceUsd) : 'in an unknown asset'} is above the ${usd(cap)} cap for ${merchant.name}`);
      const expectedDest = getAssociatedTokenAddressSync(new PublicKey(req.asset), new PublicKey(req.payTo), true).toBase58();
      const paid = tx.transfers.filter((t) => t.kind === 'spl' && t.mint === req.asset && t.destination === expectedDest);
      const paidTotal = paid.reduce((s, t) => s + t.amount, 0n);
      if (paidTotal !== BigInt(req.maxAmountRequired) || paid.length !== tx.transfers.length) {
        problems.push('payment transaction does not match the quote exactly');
      }
      if (problems.length) add('x402', 'deny', `x402 quote rejected: ${problems.join('; ')}.`);
      else add('x402', 'pass', `x402 quote from ${merchant.name} verified (${usd(priceUsd)}).`);
    }
  }

  // ---- 7. Destinations -----------------------------------------------------
  for (const t of outgoing) {
    const owner = t.destinationOwner;
    const denied = owner && [...policy.global.denyDestinations, ...agent.destinations.deny].find((d) => d.address === owner);
    if (denied) {
      add('destination', 'deny', `Destination ${denied.label} (${shortAddress(owner)}) is on the denylist.`);
      continue;
    }
    const allowed = owner && agent.destinations.allow.find((d) => d.address === owner);
    if (allowed) {
      add('destination', 'pass', `Destination ${allowed.label} is on the allowlist.`);
      continue;
    }
    if (input.kind === 'x402' && merchant && owner === input.x402!.requirements.payTo) {
      add('destination', 'pass', `Destination is the payee of x402 merchant ${merchant.name}.`);
      continue;
    }
    const msg = owner
      ? `Destination ${shortAddress(owner)} is not on the allowlist.`
      : `The owner of destination token account #${t.index} could not be determined.`;
    if (agent.approval.unknownDestinations === 'require_approval' && !input.humanApproved) add('destination', 'require_approval', msg);
    else if (agent.approval.unknownDestinations === 'require_approval') add('destination', 'pass', `${msg} Approved by a human.`);
    else add('destination', 'deny', msg);
  }

  // ---- 8. Spending limits --------------------------------------------------
  if (outgoing.length) {
    const { perTransactionUsd, dailyUsd, maxTransactionsPerMinute } = agent.limits;
    if (totalUsd > perTransactionUsd) {
      add('limit.per_transaction', 'deny', `${usd(totalUsd)} is above the ${usd(perTransactionUsd)} per-transaction limit.`);
    } else {
      add('limit.per_transaction', 'pass', `${usd(totalUsd)} is within the ${usd(perTransactionUsd)} per-transaction limit.`);
    }
    const after = input.spentLast24hUsd + totalUsd;
    if (after > dailyUsd) {
      add('limit.daily', 'deny', `Over the daily budget: ${usd(input.spentLast24hUsd)} already spent today, only ${usd(Math.max(0, dailyUsd - input.spentLast24hUsd))} of ${usd(dailyUsd)} left.`);
    } else {
      add('limit.daily', 'pass', `${usd(after)} of ${usd(dailyUsd)} daily budget used after this payment.`);
    }
    if (input.requestsLastMinute >= maxTransactionsPerMinute) {
      add('limit.velocity', 'deny', `Rate limit: already ${input.requestsLastMinute} payment attempts in the last minute (max ${maxTransactionsPerMinute}).`);
    }
    if (agent.approval.aboveUsd !== undefined && totalUsd > agent.approval.aboveUsd) {
      if (input.humanApproved) add('approval', 'pass', 'Approved by a human.');
      else add('approval', 'require_approval', `${usd(totalUsd)} is above the ${usd(agent.approval.aboveUsd)} auto-approval threshold.`);
    }
  }

  // ---- 9. Priority fee -----------------------------------------------------
  if (tx.computeUnitPriceMicroLamports !== undefined && tx.computeUnitPriceMicroLamports > BigInt(agent.maxPriorityFeeMicroLamports)) {
    add('priority_fee', 'deny', `Priority fee of ${tx.computeUnitPriceMicroLamports} micro-lamports/CU is above the ${agent.maxPriorityFeeMicroLamports} cap.`);
  }

  // ---- 10. Data-loss prevention -------------------------------------------
  if (dlpFindings.length === 0) {
    add('dlp', 'pass', 'No secrets or personal data in outbound payloads.');
  } else {
    for (const f of dlpFindings) {
      const what = `${f.type.replace(/_/g, ' ')}${f.detail ? ` (${f.detail})` : ''} detected in ${f.location}: ${f.preview}`;
      if (agent.dlp.block.includes(f.type)) add('dlp', 'deny', `Data leak blocked: ${what}.`);
      else if (agent.dlp.requireApproval.includes(f.type) && !input.humanApproved) add('dlp', 'require_approval', `Sensitive data: ${what}.`);
      else add('dlp', 'warn', `Sensitive data: ${what}.`);
    }
  }

  for (const w of tx.warnings) add('inspection', 'warn', w);
  return finish();
}

function labelFor(policy: PolicyFile, agent: AgentPolicy | undefined, owner: string | null, custody: string): string {
  if (!owner) return 'unknown account';
  if (owner === custody) return 'AgentWall wallet';
  const all = [
    ...(agent?.destinations.allow ?? []),
    ...(agent?.destinations.deny ?? []),
    ...policy.global.denyDestinations,
    ...(agent?.x402.merchants ?? []).filter((m) => m.payTo).map((m) => ({ address: m.payTo!, label: m.name })),
  ];
  return all.find((d) => d.address === owner)?.label ?? shortAddress(owner);
}
