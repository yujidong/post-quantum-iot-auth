const { ethers } = require("ethers");
require("dotenv").config();

/**
 * Base Sepolia scalability test: 500 devices, dual-relay.
 * L2 testnet for high-throughput validation.
 *
 * Usage: node scripts/l2-scalability.js
 */
async function main() {
  const RPC = process.env.BASE_SEPOLIA_RPC_URL;
  const PK1 = process.env.PRIVATE_KEY_1;
  const PK2 = process.env.PRIVATE_KEY_2;
  if (!RPC || !PK1 || !PK2) { console.error("Missing .env vars"); process.exit(1); }

  const provider = new ethers.JsonRpcProvider(RPC);
  const relay1 = new ethers.Wallet(PK1, provider);
  const relay2 = new ethers.Wallet(PK2, provider);

  const bal1 = await provider.getBalance(relay1.address);
  const bal2 = await provider.getBalance(relay2.address);

  console.log("============================================");
  console.log("  Base Sepolia Scalability: 500 Devices");
  console.log("============================================");
  console.log(`Relay 1: ${relay1.address}  (${ethers.formatEther(bal1)} ETH)`);
  console.log(`Relay 2: ${relay2.address}  (${ethers.formatEther(bal2)} ETH)`);

  // Load contract ABIs from artifacts
  const didArtifact = require("../artifacts/contracts/DIDRegistry.sol/DIDRegistry.json");
  const relayArtifact = require("../artifacts/contracts/MetaTxRelay.sol/MetaTxRelay.json");

  // --- Deploy ---
  console.log("\nDeploying contracts...");
  const DIDFactory = new ethers.ContractFactory(didArtifact.abi, didArtifact.bytecode, relay1);
  const didRegistry = await DIDFactory.deploy();
  await didRegistry.waitForDeployment();
  const didAddr = await didRegistry.getAddress();

  const RelayFactory = new ethers.ContractFactory(relayArtifact.abi, relayArtifact.bytecode, relay1);
  const metaTxRelay = await RelayFactory.deploy(didAddr);
  await metaTxRelay.waitForDeployment();
  const relayAddr = await metaTxRelay.getAddress();

  console.log(`  DIDRegistry: ${didAddr}`);
  console.log(`  MetaTxRelay: ${relayAddr}`);

  // Connect both relays
  const didReg1 = new ethers.Contract(didAddr, didArtifact.abi, relay1);
  const didReg2 = new ethers.Contract(didAddr, didArtifact.abi, relay2);
  const txRelay1 = new ethers.Contract(relayAddr, relayArtifact.abi, relay1);
  const txRelay2 = new ethers.Contract(relayAddr, relayArtifact.abi, relay2);

  // --- Generate 500 device data ---
  const TOTAL = 500;
  const PER = TOTAL / 2;
  const devices = [];
  for (let i = 0; i < TOTAL; i++) {
    devices.push({
      didHash: ethers.keccak256(ethers.toUtf8Bytes(`did:test:device:${i}`)),
      pk: ethers.randomBytes(897),
      sig: ethers.randomBytes(666),
      dataHash: ethers.keccak256(ethers.toUtf8Bytes(`payload:${i}:${Date.now()}`)),
    });
  }

  // --- Batch submit helper: fire N txns with auto-nonce, wait for last ---
  async function batchSubmit(signer, contract, method, argSets, label) {
    const BATCH = 20;
    const receipts = [];

    for (let start = 0; start < argSets.length; start += BATCH) {
      const batch = argSets.slice(start, start + BATCH);
      const sentTxns = [];

      for (const args of batch) {
        try {
          const tx = await contract[method](...args);
          sentTxns.push(tx);
        } catch (e) {
          // nonce gap - retry once
          await new Promise(r => setTimeout(r, 1000));
          try {
            const tx = await contract[method](...args);
            sentTxns.push(tx);
          } catch(e2) {}
        }
      }

      // Wait for all in this batch
      for (const tx of sentTxns) {
        try {
          const rcpt = await tx.wait();
          receipts.push(rcpt);
        } catch(e) {}
      }

      const done = start + batch.length;
      const pct = Math.round((done / argSets.length) * 100);
      process.stdout.write(`\r  ${label}: ${done}/${argSets.length} (${pct}%)   `);
    }
    console.log("");
    return receipts;
  }

  // --- Phase 1: Register DIDs ---
  console.log("\n--- Phase 1: Registering 500 DIDs (250 per relay) ---");
  const t1 = Date.now();

  const regArgs1 = devices.slice(0, PER).map(d => [d.didHash, d.pk]);
  const regArgs2 = devices.slice(PER).map(d => [d.didHash, d.pk]);

  const [regR1, regR2] = await Promise.all([
    batchSubmit(relay1, didReg1, "registerDID", regArgs1, "Relay1-DID"),
    batchSubmit(relay2, didReg2, "registerDID", regArgs2, "Relay2-DID"),
  ]);

  const allRegR = [...regR1, ...regR2].filter(r => r);
  const regGas = allRegR.map(r => Number(r.gasUsed));
  const regAvg = Math.round(regGas.reduce((a,b) => a+b, 0) / regGas.length);
  console.log(`  Registered: ${allRegR.length}/${TOTAL}`);
  console.log(`  DID gas: avg=${regAvg}, min=${Math.min(...regGas)}, max=${Math.max(...regGas)}`);
  console.log(`  Time: ${((Date.now()-t1)/1000).toFixed(1)}s`);

  // --- Phase 2: Relay Transactions ---
  console.log("\n--- Phase 2: Submitting 500 Relay Transactions ---");
  const t2 = Date.now();

  const txArgs1 = devices.slice(0, PER).map(d => [d.dataHash, d.didHash, d.sig, true]);
  const txArgs2 = devices.slice(PER).map(d => [d.dataHash, d.didHash, d.sig, true]);

  const [txR1, txR2] = await Promise.all([
    batchSubmit(relay1, txRelay1, "submitTransaction", txArgs1, "Relay1-TX"),
    batchSubmit(relay2, txRelay2, "submitTransaction", txArgs2, "Relay2-TX"),
  ]);

  const allTxR = [...txR1, ...txR2].filter(r => r);
  const txGas = allTxR.map(r => Number(r.gasUsed));
  const txAvg = Math.round(txGas.reduce((a,b) => a+b, 0) / txGas.length);
  console.log(`  Confirmed: ${allTxR.length}/${TOTAL}`);
  console.log(`  Relay TX gas: avg=${txAvg}, min=${Math.min(...txGas)}, max=${Math.max(...txGas)}`);
  console.log(`  Time: ${((Date.now()-t2)/1000).toFixed(1)}s`);

  // --- Verify ---
  const txCount = await metaTxRelay.transactionCount();
  const bal1After = await provider.getBalance(relay1.address);
  const bal2After = await provider.getBalance(relay2.address);

  // --- Summary ---
  console.log("\n============================================");
  console.log("  SCALABILITY SUMMARY (Base Sepolia, 500 devices)");
  console.log("============================================");
  console.log(`Devices:             ${TOTAL}`);
  console.log(`Relay operators:     2 (parallel, 250 each)`);
  console.log(`DID Register gas:    avg=${regAvg}, min=${Math.min(...regGas)}, max=${Math.max(...regGas)}`);
  console.log(`Relay TX gas:        avg=${txAvg}, min=${Math.min(...txGas)}, max=${Math.max(...txGas)}`);
  console.log(`Confirmed txns:      ${allTxR.length}/${TOTAL}`);
  console.log(`On-chain count:      ${txCount}`);
  console.log(`Total time:          ${((Date.now()-t1)/1000/60).toFixed(1)} min`);
  console.log(`ETH spent:           ${ethers.formatEther(bal1 + bal2 - bal1After - bal2After)}`);
  console.log(`\nContract addresses:`);
  console.log(`  DIDRegistry: ${didAddr}`);
  console.log(`  MetaTxRelay: ${relayAddr}`);
  console.log(`\nHardhat reference: DID reg=771537, Relay TX=821563`);
  console.log("Done.");
}

main().then(() => process.exit(0)).catch(e => { console.error(e); process.exit(1); });
