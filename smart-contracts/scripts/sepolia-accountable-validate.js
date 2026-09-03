/**
 * Sepolia L1 validation of AccountableRelay (V3) with INDEPENDENT roles:
 *   relay       = the funded account from .env (key 1)
 *   challenger  = derived key 2 (funded by key 1)
 *   verifiers   = derived keys 2 and 3 (funded by key 1), quorum t = 2
 *
 * Exercised: stakes + committee registration (3 members), accountable
 * submissions, bound-leaf batch, finalization after the window, and a
 * fraud dispute attested by two verifier keys that are neither the relay
 * nor (for the resolving quorum) the challenger, ending in revocation,
 * relay slashing, challenger bounty, and attester rewards.
 *
 * Validation configuration: challengePeriod = 90 s, economics scaled 1/100.
 * The derived keys exist only for this run.
 */
const { ethers } = require("hardhat");
const fs = require("fs");
const path = require("path");

const FALCON_PK_SIZE = 897;
const FALCON_SIG_SIZE = 752;
const CHALLENGE_PERIOD = 90;
const QUORUM = 2n;
const RELAY_STAKE = ethers.parseEther("0.01");
const VERIFIER_STAKE = ethers.parseEther("0.005");
const CHALLENGER_BOND = ethers.parseEther("0.001");
const RELAY_SLASH = ethers.parseEther("0.005");

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitOk(tx) {
  const r = await tx.wait();
  if (r.status !== 1) throw new Error("tx reverted: " + tx.hash);
  return Number(r.gasUsed);
}

async function main() {
  const provider = new ethers.JsonRpcProvider(process.env.SEPOLIA_RPC_URL);
  const relayWallet = new ethers.Wallet(process.env.PRIVATE_KEY, provider);
  console.log("relay/deployer:", relayWallet.address, "balance:", ethers.formatEther(await provider.getBalance(relayWallet.address)));

  // Three fully independent derived keys: challenger and two committee
  // verifiers. No key plays two roles; the relay key plays none besides relay.
  const challengerWallet = ethers.Wallet.createRandom().connect(provider);
  const verifierAWallet = ethers.Wallet.createRandom().connect(provider);
  const verifierBWallet = ethers.Wallet.createRandom().connect(provider);
  console.log("challenger:", challengerWallet.address);
  console.log("verifier A:", verifierAWallet.address);
  console.log("verifier B:", verifierBWallet.address);
  const FUND = ethers.parseEther("0.03");
  await waitOk(await relayWallet.sendTransaction({ to: challengerWallet.address, value: FUND }));
  await waitOk(await relayWallet.sendTransaction({ to: verifierAWallet.address, value: FUND }));
  await waitOk(await relayWallet.sendTransaction({ to: verifierBWallet.address, value: FUND }));

  const results = {
    timestamp: new Date().toISOString(),
    network: "sepolia",
    challengePeriod: CHALLENGE_PERIOD,
    quorum: Number(QUORUM),
    roles: {
      relay: relayWallet.address,
      challenger: challengerWallet.address,
      verifiers: [verifierAWallet.address, verifierBWallet.address],
    },
  };

  const DIDRegistry = await ethers.getContractFactory("DIDRegistry", relayWallet);
  const didRegistry = await DIDRegistry.deploy();
  await didRegistry.waitForDeployment();
  results.didRegistryDeployment = await waitOk(didRegistry.deploymentTransaction());

  const AccountableRelay = await ethers.getContractFactory("AccountableRelay", relayWallet);
  const ar = await AccountableRelay.deploy(
    await didRegistry.getAddress(), CHALLENGE_PERIOD, QUORUM,
    RELAY_STAKE, VERIFIER_STAKE, CHALLENGER_BOND, RELAY_SLASH, ethers.parseEther("0.0025")
  );
  await ar.waitForDeployment();
  results.deployment = await waitOk(ar.deploymentTransaction());
  console.log("deployed AccountableRelay at", await ar.getAddress(), "gas:", results.deployment);

  async function registerDIDConfirmed(did) {
    for (let a = 0; a < 3; a++) {
      if (await didRegistry.isActive(did)) return;
      try { await waitOk(await didRegistry.registerDID(did, ethers.randomBytes(FALCON_PK_SIZE))); } catch { /* retry */ }
      for (let i = 0; i < 10 && !(await didRegistry.isActive(did)); i++) await sleep(3000);
    }
    if (!(await didRegistry.isActive(did))) throw new Error("DID not confirmed: " + did);
  }

  // Stakes + committee: verifiers are the two independent keys.
  results.stakeRelay = await waitOk(await ar.stakeRelay({ value: RELAY_STAKE }));
  const challengerAR = ar.connect(challengerWallet);
  const verifierAAR = ar.connect(verifierAWallet);
  const verifierBAR = ar.connect(verifierBWallet);
  results.stakeVerifier1 = await waitOk(await verifierAAR.stakeVerifier({ value: VERIFIER_STAKE }));
  results.stakeVerifier2 = await waitOk(await verifierBAR.stakeVerifier({ value: VERIFIER_STAKE }));
  results.committeeSize = Number(await ar.verifierCount());

  // Submissions + batch.
  const did = ethers.id("did:falconiot:sepolia-v3-mk-0");
  await registerDIDConfirmed(did);
  const subs = [];
  for (let i = 0; i < 2; i++) {
    subs.push(await waitOk(await ar.submitAccountable(ethers.id(`v3-mk-${i}`), did, ethers.randomBytes(FALCON_SIG_SIZE))));
  }
  results.submitAccountable = subs;

  const batchDids = [], batchData = [], batchSigs = [];
  for (let i = 0; i < 10; i++) {
    const d = ethers.id(`did:falconiot:sepolia-v3-mk-batch-${i}`);
    await registerDIDConfirmed(d);
    batchDids.push(d);
    batchData.push(ethers.id(`v3-mk-batch-${i}`));
    batchSigs.push(ethers.randomBytes(FALCON_SIG_SIZE));
  }
  results.submitBatch10 = await waitOk(await ar.submitBatch(batchDids, batchData, ethers.concat(batchSigs)));

  // Finalize after the window.
  console.log("waiting", CHALLENGE_PERIOD + 15, "s...");
  await sleep((CHALLENGE_PERIOD + 15) * 1000);
  results.finalizeRecord = await waitOk(await ar.finalizeRecord(0));
  results.invariantFinalized = Number((await ar.getRecord(0)).state) === 1;

  // Fraud dispute on record 1: challenger opens; both independent
  // verifiers attest fraud (quorum 2). Neither is the relay.
  const relayStakeBefore = await ar.relayStake(relayWallet.address);

  results.openDispute = await waitOk(await challengerAR.openDispute(1, { value: CHALLENGER_BOND }));
  const disputeId = Number(await ar.disputeCount()) - 1;
  const digest = await ar.computeAttestDigest(disputeId, true);
  const sigA = await verifierAWallet.signMessage(ethers.getBytes(digest));
  const sigB = await verifierBWallet.signMessage(ethers.getBytes(digest));
  results.submitAttestation1 = await waitOk(await verifierAAR.submitAttestation(disputeId, true, sigA));
  results.submitAttestationResolving = await waitOk(await verifierBAR.submitAttestation(disputeId, true, sigB));

  results.invariantFraudRevoked = Number((await ar.getRecord(1)).state) === 3;
  results.invariantRelaySlashed = (await ar.relayStake(relayWallet.address)) === relayStakeBefore - RELAY_SLASH * 3n / 5n;
  // Pull payments: credits are claimable via withdraw().
  results.invariantChallengerCredited =
    (await ar.pendingWithdrawals(challengerWallet.address)) === RELAY_SLASH * 3n / 5n + CHALLENGER_BOND;
  results.invariantVerifierCredited =
    (await ar.pendingWithdrawals(verifierAWallet.address)) === RELAY_SLASH * 2n / 5n / 2n &&
    (await ar.pendingWithdrawals(verifierBWallet.address)) === RELAY_SLASH * 2n / 5n / 2n;
  const wTx = await challengerAR.withdraw();
  results.withdraw = Number((await wTx.wait()).gasUsed);
  results.invariantWithdrawPaysAll = (await ar.pendingWithdrawals(challengerWallet.address)) === 0n;

  // ---- persist ----
  const outDir = path.join(__dirname, "..", "results");
  if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(path.join(outDir, "accountable-sepolia-validation.json"), JSON.stringify(results, null, 2));
  console.log("\n" + JSON.stringify(results, null, 2));
}

main().catch((e) => { console.error(e); process.exitCode = 1; });
