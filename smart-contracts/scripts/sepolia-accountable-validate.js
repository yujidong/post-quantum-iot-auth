/**
 * Sepolia L1 validation of the AccountableRelay (V2) contract:
 * deploys the accountability protocol on live Ethereum Sepolia and
 * reproduces the Hardhat lifecycle measurements end to end.
 *
 * Deployment parameters for validation: challengePeriod = 90 s (so the
 * full lifecycle can run in one session; production uses 2 h) and
 * quorum = 1 (a single key controls all roles in this run; production
 * uses an independent staked committee).
 *
 * Lifecycle exercised:
 *   stake -> accountable submission -> bound-leaf batch ->
 *   finalize after window -> dispute -> attest -> revoke + slash
 */
const { ethers } = require("hardhat");
const fs = require("fs");
const path = require("path");

const FALCON_PK_SIZE = 897;
const FALCON_SIG_SIZE = 752;
const CHALLENGE_PERIOD = 90; // seconds (validation configuration)
const QUORUM = 1n;
// Scaled economics (1/100 of the reference benchmark) so the full
// lifecycle fits a modest testnet balance; production tunes per Table 5.
const RELAY_STAKE = ethers.parseEther("0.01");
const VERIFIER_STAKE = ethers.parseEther("0.005");
const CHALLENGER_BOND = ethers.parseEther("0.001");
const RELAY_SLASH = ethers.parseEther("0.005");

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function gasOf(tx) {
  const receipt = await tx.wait();
  if (receipt.status !== 1) throw new Error("transaction reverted: " + tx.hash);
  return { gas: Number(receipt.gasUsed), receipt };
}

/**
 * Register a DID and wait until the registration is actually visible in a
 * mined block (public RPCs can reorder or delay unconfirmed sends).
 */
async function registerDIDConfirmed(didRegistry, did, pubKey) {
  for (let attempt = 1; attempt <= 3; attempt++) {
    if (await didRegistry.isActive(did)) return;
    try {
      await gasOf(await didRegistry.registerDID(did, pubKey));
    } catch (e) {
      console.log(`registerDID attempt ${attempt} failed: ${e.shortMessage || e.message.slice(0, 120)}`);
      await sleep(5000 * attempt);
    }
    // Wait for visibility even after a successful send.
    for (let i = 0; i < 10 && !(await didRegistry.isActive(did)); i++) await sleep(3000);
  }
  if (!(await didRegistry.isActive(did))) throw new Error("DID registration not confirmed: " + did);
}

async function main() {
  const provider = new ethers.JsonRpcProvider(process.env.SEPOLIA_RPC_URL);
  const wallet = new ethers.Wallet(process.env.PRIVATE_KEY, provider);
  const net = await provider.getNetwork();
  console.log("network:", net.name, "chainId:", net.chainId.toString());
  console.log("deployer:", wallet.address);
  const bal = await provider.getBalance(wallet.address);
  console.log("balance:", ethers.formatEther(bal), "ETH");
  if (bal < ethers.parseEther("0.05")) throw new Error("insufficient Sepolia ETH for the validation run");

  const results = { timestamp: new Date().toISOString(), network: "sepolia", challengePeriod: CHALLENGE_PERIOD, quorum: Number(QUORUM) };

  // --- deploy ---
  const DIDRegistry = await ethers.getContractFactory("DIDRegistry", wallet);
  const didRegistry = await DIDRegistry.deploy();
  await didRegistry.waitForDeployment();
  results.didRegistryDeployment = (await gasOf(didRegistry.deploymentTransaction())).gas;

  const AccountableRelay = await ethers.getContractFactory("AccountableRelay", wallet);
  const ar = await AccountableRelay.deploy(
    await didRegistry.getAddress(),
    CHALLENGE_PERIOD,
    QUORUM,
    RELAY_STAKE,
    VERIFIER_STAKE,
    CHALLENGER_BOND,
    RELAY_SLASH,
    ethers.parseEther("0.0025") // verifier slash
  );
  await ar.waitForDeployment();
  const dep = await gasOf(ar.deploymentTransaction());
  results.accountableRelayDeployment = dep.gas;
  console.log("deployed AccountableRelay at", await ar.getAddress(), "deployment gas:", dep.gas);

  // --- stakes ---
  results.stakeRelay = (await gasOf(await ar.stakeRelay({ value: RELAY_STAKE }))).gas;
  results.stakeVerifier = (await gasOf(await ar.stakeVerifier({ value: VERIFIER_STAKE }))).gas;

  // --- DID + accountable submissions ---
  const did = ethers.id("did:falconiot:sepolia-accountable-0");
  await registerDIDConfirmed(didRegistry, did, ethers.randomBytes(FALCON_PK_SIZE));

  const subGas = [];
  for (let i = 0; i < 3; i++) {
    subGas.push((await gasOf(await ar.submitAccountable(ethers.id(`sepolia-v2-data-${i}`), did, ethers.randomBytes(FALCON_SIG_SIZE)))).gas);
  }
  results.submitAccountable = subGas;
  console.log("accountable submissions:", subGas);

  // --- bound-leaf batch (k = 10, fresh DIDs) ---
  const dids = [];
  const dataHashes = [];
  const sigs = [];
  for (let i = 0; i < 10; i++) {
    const d = ethers.id(`did:falconiot:sepolia-batch-${i}`);
    await registerDIDConfirmed(didRegistry, d, ethers.randomBytes(FALCON_PK_SIZE));
    dids.push(d);
    dataHashes.push(ethers.id(`sepolia-batch-data-${i}`));
    sigs.push(ethers.randomBytes(FALCON_SIG_SIZE));
  }
  const batch = await gasOf(await ar.submitBatch(dids, dataHashes, ethers.concat(sigs)));
  results.submitBatch10 = batch.gas;
  console.log("batch k=10 gas:", batch.gas);

  // --- finalize after the challenge window ---
  console.log("waiting", CHALLENGE_PERIOD + 15, "s for the challenge window...");
  await sleep((CHALLENGE_PERIOD + 15) * 1000);
  const fin = await gasOf(await ar.finalizeRecord(0));
  results.finalizeRecord = fin.gas;
  const rec0 = await ar.getRecord(0);
  results.invariantFinalized = Number(rec0.state) === 1;

  // --- dispute path: fraud quorum (quorum = 1 in this validation) ---
  const fraudDid = ethers.id("did:falconiot:sepolia-fraud");
  await registerDIDConfirmed(didRegistry, fraudDid, ethers.randomBytes(FALCON_PK_SIZE));
  await ar.submitAccountable(ethers.id("sepolia-fraud-data"), fraudDid, ethers.randomBytes(FALCON_SIG_SIZE));
  const fraudIndex = Number((await ar.recordCount()) - 1n);

  const od = await gasOf(await ar.openDispute(fraudIndex, { value: CHALLENGER_BOND }));
  results.openDispute = od.gas;
  const disputeId = Number((await ar.disputeCount()) - 1n);

  const digest = await ar.computeAttestDigest(disputeId, true);
  const attSig = await wallet.signMessage(ethers.getBytes(digest));
  const att = await gasOf(await ar.submitAttestation(disputeId, true, attSig));
  results.submitAttestationResolving = att.gas;

  const recF = await ar.getRecord(fraudIndex);
  results.invariantFraudRevoked = Number(recF.state) === 3;
  results.invariantRelaySlashed = (await ar.relayStake(wallet.address)) === RELAY_STAKE - RELAY_SLASH;
  const stakeAfter = await ar.relayStake(wallet.address);
  console.log("relay stake after slash:", ethers.formatEther(stakeAfter), "ETH");

  // --- persist ---
  const outDir = path.join(__dirname, "..", "results");
  if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
  const outPath = path.join(outDir, "accountable-sepolia-validation.json");
  fs.writeFileSync(outPath, JSON.stringify(results, null, 2));
  console.log("\n" + JSON.stringify(results, null, 2));
  console.log("\nsaved:", outPath);

  const spent = bal - (await provider.getBalance(wallet.address));
  console.log("total ETH spent (incl. stakes retained in contract):", ethers.formatEther(spent));
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
