/**
 * Base Sepolia (OP Stack L2) scalability run for AccountableRelay (V3):
 * 10/50/100/200/500 devices, each = one DID registration + one accountable
 * submission, plus a batched comparison at 100 devices (10 batches of k=10).
 *
 * Rationale: the L1/L2 table in the paper reports the V1 baseline contracts;
 * this run provides the same workload for the accountable path. Base Sepolia
 * is used because identical EVM gas at ~0.006 gwei makes a 1,700+ transaction
 * workload affordable.
 */
const { ethers } = require("hardhat");
const fs = require("fs");
const path = require("path");

const FALCON_PK_SIZE = 897;
const FALCON_SIG_SIZE = 752;
const CHALLENGE_PERIOD = 7200;
const QUORUM = 2n;
const ONE = ethers.parseEther("1");

const CONFIGS = [10, 50, 100, 200, 500];
const SEND_CONCURRENCY = 20;

async function main() {
  const provider = new ethers.JsonRpcProvider(process.env.BASE_SEPOLIA_RPC_URL);
  const wallet = new ethers.Wallet(process.env.PRIVATE_KEY, provider);
  // Drain check: wait until the mempool holds no tx from a previous run;
  // if one is stuck, actively replace it with a higher-fee self-transfer.
  for (let i = 0; i < 30; i++) {
    const latest = await provider.getTransactionCount(wallet.address, "latest");
    const pending = await provider.getTransactionCount(wallet.address, "pending");
    if (latest === pending) break;
    console.log(`stale tx at nonce ${latest} (${pending - latest} pending); replacing...`);
    try {
      const fee = await provider.getFeeData();
      const bump = (fee.maxFeePerGas * 15n) / 10n;
      const tx = await wallet.sendTransaction({
        to: wallet.address, value: 0, nonce: latest,
        maxFeePerGas: bump, maxPriorityFeePerGas: fee.maxPriorityFeePerGas ? (fee.maxPriorityFeePerGas * 15n) / 10n : bump,
        gasLimit: 21000,
      });
      await tx.wait();
    } catch (e) {
      console.log("replace attempt:", e.shortMessage || e.message.slice(0, 100));
      await new Promise((r) => setTimeout(r, 4000));
    }
  }
  wallet.nonce = await provider.getTransactionCount(wallet.address, "pending");
  console.log("relay:", wallet.address, "balance:", ethers.formatEther(await provider.getBalance(wallet.address)));

  const results = { timestamp: new Date().toISOString(), network: "base-sepolia", configs: [] };

  const DIDRegistry = await ethers.getContractFactory("DIDRegistry", wallet);
  const didRegistry = await DIDRegistry.deploy();
  await didRegistry.waitForDeployment();
  const AccountableRelay = await ethers.getContractFactory("AccountableRelay", wallet);
  const ar = await AccountableRelay.deploy(
    await didRegistry.getAddress(), CHALLENGE_PERIOD, QUORUM,
    ethers.parseEther("0.01"), ethers.parseEther("0.005"), ethers.parseEther("0.001"),
    ethers.parseEther("0.005"), ethers.parseEther("0.0025")
  );
  await ar.waitForDeployment();
  // Public L2 RPCs can serve stale state right after the deploy receipt;
  // wait until the runtime code is actually visible.
  const arAddr = await ar.getAddress();
  for (let i = 0; i < 30; i++) {
    const code = await provider.getCode(arAddr);
    if (code && code !== "0x") break;
    console.log("waiting for contract code to be visible...");
    await new Promise((r) => setTimeout(r, 4000));
  }
  console.log("deployed at", arAddr);
  await (await ar.stakeRelay({ value: ethers.parseEther("0.01"), gasLimit: 200000 })).wait();

  // Explicit nonce management: the wallet's internal counter desyncs over
  // long runs on public L2 RPCs; track nonces manually and re-sync from the
  // chain whenever the node reports a nonce error.
  let nextNonce = null;
  const syncNonce = async () => {
    nextNonce = Number(await provider.getTransactionCount(wallet.address, "pending"));
  };
  const sendWithNonce = async (fn) => {
    if (nextNonce === null) await syncNonce();
    for (let a = 0; a < 8; a++) {
      try {
        const tx = await fn({ nonce: nextNonce, gasLimit: 5_000_000 });
        nextNonce += 1;
        return tx;
      } catch (e) {
        const msg = String(e);
        if (msg.includes("nonce") || msg.includes("already known") || msg.includes("replacement")) {
          await syncNonce();
          continue;
        }
        throw e;
      }
    }
    throw new Error("sendWithNonce: retries exhausted");
  };

  let deviceCounter = 0;
  for (const n of CONFIGS) {
    const dids = [], datas = [], sigs = [];
    for (let i = 0; i < n; i++) {
      dids.push(ethers.id(`did:falconiot:bs-v3-${deviceCounter++}`));
      datas.push(ethers.id(`bs-v3-data-${deviceCounter}`));
      sigs.push(ethers.randomBytes(FALCON_SIG_SIZE));
    }
    const t0 = Date.now();

    // Broadcasts are serialized (Wallet signers race on nonces if fired
    // concurrently); receipt collection is parallel.
    const sendWave = async (calls) => {
      const sent = [];
      for (const c of calls) sent.push(await sendWithNonce(c));
      return Promise.all(sent.map((r) => r.wait()));
    };

    const receipts = [];
    for (let i = 0; i < n; i += SEND_CONCURRENCY) {
      const calls = [];
      for (let j = i; j < Math.min(i + SEND_CONCURRENCY, n); j++) {
        calls.push(() => didRegistry.registerDID(dids[j], ethers.randomBytes(FALCON_PK_SIZE)));
      }
      receipts.push(...(await sendWave(calls)));
    }
    const tRegs = Date.now();

    const subReceipts = [];
    for (let i = 0; i < n; i += SEND_CONCURRENCY) {
      const calls = [];
      for (let j = i; j < Math.min(i + SEND_CONCURRENCY, n); j++) {
        calls.push(() => ar.submitAccountable(datas[j], dids[j], sigs[j]));
      }
      subReceipts.push(...(await sendWave(calls)));
    }
    const t1 = Date.now();

    const failed = subReceipts.filter((r) => r.status !== 1).length;
    const gasSum = subReceipts.reduce((a, r) => a + r.gasUsed, 0n);
    const entry = {
      devices: n,
      confirmed: subReceipts.length - failed,
      failed,
      regWallMs: tRegs - t0,
      submitWallMs: t1 - tRegs,
      totalWallS: (t1 - t0) / 1000,
      avgSubmitGas: Number(gasSum / BigInt(n)),
      avgRegGas: Number(receipts.reduce((a, r) => a + r.gasUsed, 0n) / BigInt(n)),
    };
    results.configs.push(entry);
    console.log(JSON.stringify(entry));
  }

  // Batched comparison at 100 devices: 10 batches of k = 10.
  {
    const k = 10, batches = 10, n = k * batches;
    const dids = [], datas = [], sigs = [];
    for (let i = 0; i < n; i++) {
      dids.push(ethers.id(`did:falconiot:bs-v3-batched-${i}`));
      datas.push(ethers.id(`bs-v3-batched-data-${i}`));
      sigs.push(ethers.randomBytes(FALCON_SIG_SIZE));
    }
    const t0 = Date.now();
    for (let i = 0; i < n; i += SEND_CONCURRENCY) {
      const calls = [];
      for (let j = i; j < Math.min(i + SEND_CONCURRENCY, n); j++) {
        calls.push(() => didRegistry.registerDID(dids[j], ethers.randomBytes(FALCON_PK_SIZE)));
      }
      const sent = [];
      for (const c of calls) sent.push(await sendWithNonce(c));
      await Promise.all(sent.map((r) => r.wait()));
    }
    const t1 = Date.now();
    const batchReceipts = [];
    for (let b = 0; b < batches; b++) {
      const slice = sigs.slice(b * k, (b + 1) * k);
      const tx = await ar.submitBatch(dids.slice(b * k, (b + 1) * k), datas.slice(b * k, (b + 1) * k), ethers.concat(slice));
      batchReceipts.push(await tx.wait());
    }
    const t2 = Date.now();
    const gasSum = batchReceipts.reduce((a, r) => a + r.gasUsed, 0n);
    results.batched100 = {
      devices: n,
      batches,
      batchSize: k,
      submitWallMs: t2 - t1,
      totalWallS: (t2 - t0) / 1000,
      avgBatchGas: Number(gasSum / BigInt(batches)),
      perTxGas: Number(gasSum / BigInt(n)),
      confirmed: batchReceipts.filter((r) => r.status === 1).length,
    };
    console.log(JSON.stringify(results.batched100));
  }

  const outDir = path.join(__dirname, "..", "results");
  if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(path.join(outDir, "accountable-scalability-base.json"), JSON.stringify(results, null, 2));
  console.log("saved results/accountable-scalability-base.json");
}

main().catch((e) => { console.error(e); process.exitCode = 1; });
