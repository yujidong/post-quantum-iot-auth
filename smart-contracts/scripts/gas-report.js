const { ethers } = require("hardhat");
const fs = require("fs");
const path = require("path");

const FALCON_PK_SIZE = 897;
const FALCON_SIG_SIZE = 752;

async function main() {
  console.log("Running gas measurement report...\n");

  const [deployer, owner, relay] = await ethers.getSigners();

  // Deploy contracts
  const DIDRegistry = await ethers.getContractFactory("DIDRegistry");
  const didRegistry = await DIDRegistry.deploy();
  await didRegistry.waitForDeployment();

  const MetaTxRelay = await ethers.getContractFactory("MetaTxRelay");
  const metaTxRelay = await MetaTxRelay.deploy(await didRegistry.getAddress());
  await metaTxRelay.waitForDeployment();

  const results = {};

  // --- DIDRegistry gas measurements ---
  console.log("=== DIDRegistry ===\n");

  // 1. DID Registration
  const regGasCosts = [];
  for (let i = 0; i < 10; i++) {
    const didHash = ethers.id(`did:falconiot:gas-report-${i}`);
    const pubKey = ethers.randomBytes(FALCON_PK_SIZE);
    const tx = await didRegistry.connect(owner).registerDID(didHash, pubKey);
    const receipt = await tx.wait();
    regGasCosts.push(Number(receipt.gasUsed));
  }
  results.didRegistration = summarize("DID Registration", regGasCosts);

  // 2. Public Key Lookup
  const lookupDidHash = ethers.id("did:falconiot:lookup-gas");
  await didRegistry.connect(owner).registerDID(lookupDidHash, ethers.randomBytes(FALCON_PK_SIZE));

  const lookupGasCosts = [];
  for (let i = 0; i < 10; i++) {
    const gas = await didRegistry.getPublicKey.estimateGas(lookupDidHash);
    lookupGasCosts.push(Number(gas));
  }
  results.publicKeyLookup = summarize("Public Key Lookup", lookupGasCosts);

  // 3. DID Deactivation
  const deactDidHash = ethers.id("did:falconiot:deact-gas");
  await didRegistry.connect(owner).registerDID(deactDidHash, ethers.randomBytes(FALCON_PK_SIZE));
  const deactTx = await didRegistry.connect(owner).deactivateDID(deactDidHash);
  const deactReceipt = await deactTx.wait();
  results.didDeactivation = {
    gas: Number(deactReceipt.gasUsed),
    label: "DID Deactivation",
  };
  console.log(`  DID Deactivation gas: ${deactReceipt.gasUsed.toString()}`);

  // --- MetaTxRelay gas measurements ---
  console.log("\n=== MetaTxRelay ===\n");

  // Register a DID for relay tests
  const relayDidHash = ethers.id("did:falconiot:relay-gas");
  const relayPubKey = ethers.randomBytes(FALCON_PK_SIZE);
  await didRegistry.connect(owner).registerDID(relayDidHash, relayPubKey);

  // 4. Relay Transaction Submission
  const relayGasCosts = [];
  for (let i = 0; i < 10; i++) {
    const dataHash = ethers.id(`relay-gas-data-${i}`);
    const sig = ethers.randomBytes(FALCON_SIG_SIZE);
    const tx = await metaTxRelay.connect(relay).submitTransaction(dataHash, relayDidHash, sig, true);
    const receipt = await tx.wait();
    relayGasCosts.push(Number(receipt.gasUsed));
  }
  results.relayTransaction = summarize("Relay Transaction", relayGasCosts);

  // 5. Transaction Retrieval
  const retrievalGasCosts = [];
  for (let i = 0; i < 10; i++) {
    const gas = await metaTxRelay.getTransactionForVerification.estimateGas(i);
    retrievalGasCosts.push(Number(gas));
  }
  results.transactionRetrieval = summarize("Transaction Retrieval", retrievalGasCosts);

  // --- Comparison ---
  console.log("\n=== Comparison with Theoretical On-Chain Falcon ===\n");
  const theoreticalFalconGas = 500_000_000;
  const relayMean = results.relayTransaction.mean;
  const ratio = Math.round(theoreticalFalconGas / relayMean);
  console.log(`  Theoretical on-chain Falcon verification: ~${theoreticalFalconGas.toLocaleString()} gas`);
  console.log(`  Actual relay-assisted (mean): ${Math.round(relayMean).toLocaleString()} gas`);
  console.log(`  Reduction ratio: ~${ratio}x`);

  // Save results
  const outputDir = path.join(__dirname, "..", "results");
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  const reportData = {
    timestamp: new Date().toISOString(),
    network: "hardhat",
    solidityVersion: "0.8.24",
    optimizer: { enabled: true, runs: 200 },
    falconParams: {
      publicKeySize: FALCON_PK_SIZE,
      signatureSize: FALCON_SIG_SIZE,
    },
    results: {
      didRegistration: results.didRegistration,
      publicKeyLookup: results.publicKeyLookup,
      didDeactivation: results.didDeactivation,
      relayTransaction: results.relayTransaction,
      transactionRetrieval: results.transactionRetrieval,
    },
    comparison: {
      theoreticalFalconGas,
      relayMeanGas: relayMean,
      reductionRatio: ratio,
    },
  };

  const jsonPath = path.join(outputDir, "gas-report.json");
  fs.writeFileSync(jsonPath, JSON.stringify(reportData, null, 2));
  console.log(`\nResults saved to: ${jsonPath}`);

  // Also save CSV
  const csvLines = [
    "operation,mean_gas,std_dev,min_gas,max_gas,samples",
    `did_registration,${results.didRegistration.mean},${results.didRegistration.stdDev},${results.didRegistration.min},${results.didRegistration.max},${results.didRegistration.n}`,
    `public_key_lookup,${results.publicKeyLookup.mean},${results.publicKeyLookup.stdDev},${results.publicKeyLookup.min},${results.publicKeyLookup.max},${results.publicKeyLookup.n}`,
    `did_deactivation,${results.didDeactivation.gas},0,${results.didDeactivation.gas},${results.didDeactivation.gas},1`,
    `relay_transaction,${results.relayTransaction.mean},${results.relayTransaction.stdDev},${results.relayTransaction.min},${results.relayTransaction.max},${results.relayTransaction.n}`,
    `transaction_retrieval,${results.transactionRetrieval.mean},${results.transactionRetrieval.stdDev},${results.transactionRetrieval.min},${results.transactionRetrieval.max},${results.transactionRetrieval.n}`,
  ];
  const csvPath = path.join(outputDir, "gas-report.csv");
  fs.writeFileSync(csvPath, csvLines.join("\n"));
  console.log(`CSV saved to: ${csvPath}`);
}

function summarize(label, values) {
  const n = values.length;
  const mean = values.reduce((a, b) => a + b, 0) / n;
  const variance = values.reduce((sum, x) => sum + (x - mean) ** 2, 0) / n;
  const stddev = Math.sqrt(variance);
  const min = Math.min(...values);
  const max = Math.max(...values);

  console.log(`  ${label} (n=${n}):`);
  console.log(`    Mean: ${mean.toFixed(0)}`);
  console.log(`    Std Dev: ${stddev.toFixed(0)}`);
  console.log(`    Min: ${min}, Max: ${max}`);

  return { mean, stddev, min, max, n, label };
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
