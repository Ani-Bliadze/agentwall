import { Connection, PublicKey, Transaction, VersionedTransaction } from '@solana/web3.js';
import { AccountLayout, TOKEN_PROGRAM_ID, getAssociatedTokenAddressSync } from '@solana/spl-token';
import type { TokenAccountInfo } from './inspector.js';
import { LedgerError, type Ledger } from './ledger.js';

/** A real Solana cluster (devnet or mainnet) over JSON-RPC. */
export class RpcLedger implements Ledger {
  readonly kind = 'rpc' as const;
  readonly connection: Connection;

  constructor(rpcUrl: string) {
    this.connection = new Connection(rpcUrl, 'confirmed');
  }

  async latestBlockhash() {
    return (await this.connection.getLatestBlockhash('confirmed')).blockhash;
  }

  async getSolBalance(owner: PublicKey) {
    return BigInt(await this.connection.getBalance(owner, 'confirmed'));
  }

  async getTokenBalance(owner: PublicKey, mint: PublicKey, tokenProgram = TOKEN_PROGRAM_ID) {
    const ata = getAssociatedTokenAddressSync(mint, owner, true, tokenProgram);
    const info = await this.connection.getAccountInfo(ata, 'confirmed');
    if (!info) return 0n;
    return AccountLayout.decode(info.data.subarray(0, AccountLayout.span)).amount;
  }

  async getTokenAccount(address: string): Promise<TokenAccountInfo | null> {
    const info = await this.connection.getAccountInfo(new PublicKey(address), 'confirmed');
    if (!info || info.data.length < AccountLayout.span) return null;
    const decoded = AccountLayout.decode(info.data.subarray(0, AccountLayout.span));
    return { mint: decoded.mint.toBase58(), owner: decoded.owner.toBase58() };
  }

  async sendTransaction(tx: Transaction | VersionedTransaction): Promise<string> {
    const raw = tx.serialize();
    const blockhash = tx instanceof Transaction ? tx.recentBlockhash! : tx.message.recentBlockhash;
    const signature = await this.connection.sendRawTransaction(raw, { skipPreflight: false });
    const { lastValidBlockHeight } = await this.connection.getLatestBlockhash('confirmed');
    const res = await this.connection.confirmTransaction({ signature, blockhash, lastValidBlockHeight }, 'confirmed');
    if (res.value.err) throw new LedgerError(`Transaction ${signature} failed: ${JSON.stringify(res.value.err)}`);
    return signature;
  }
}
