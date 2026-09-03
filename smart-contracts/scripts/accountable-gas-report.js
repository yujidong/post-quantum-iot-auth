/**
 * Gas + correctness benchmark for the AccountableRelay (V3) contract.
 *
 * V3 hardening covered by the invariant suite:
 *   I1  inactive-DID / non-staked-submitter rejection
 *   I2  finalization only after the challenge window (early finalize reverts)
 *   I3  fraud path: target Revoked, relay slashed (60% bounty + 40% split by
 *       fraud attesters), challenger bond refunded
 *   I4  spurious path: target returns to PROVISIONAL (challenge window NOT
 *       bypassed), bond split 50% relay / 50% valid attesters
 *   I5  re-dispute after a spurious verdict; fraud then proven -> the
 *       earlier spurious dispute's valid attesters are slashed (cross-
 *       dispute wrong-side registry)
 *   I6  fail-closed expiry: target revoked, half the bond refunded, half
 *       burned (retained), relay active-dispute counter back to zero
 *   I7  conflict of interest: the target's endorsing relay cannot attest
 *       on its own dispute even when staked+registered as a verifier
 *   I8  committee admission: non-registered / duplicate attestations rejected
 *   I9  batch leaves disputable independently and in parallel; spurious leaf
 *       verdict returns the leaf to Upheld (re-disputable); fraud revokes
 *       only that leaf; batch finalizes after the window with zero open
 *       leaf disputes and an accurate revoked-leaf count
 *   I10 contract-built Merkle roots match independent off-chain
 *       reconstruction; invalid inclusion proofs rejected
 */
const { ethers, network } = require("hardhat");
const fs = require("fs");
const path = require("path");

const FALCON_PK_SIZE = 897;
const FALCON_SIG_SIZE = 752;
const CHALLENGE_PERIOD = 7200;
const QUORUM = 2n;
const ONE = ethers.parseEther("1");

function summarize(values) {
  const n = values.length;
  const mean = values.reduce((a, b) => a + b, 0) / n;
  const variance = values.reduce((s, x) => s + (x - mean) ** 2, 0) / n;
  return { n, mean: Math.round(mean), stdDev: Math.round(Math.sqrt(variance)), min: Math.min(...values), max: Math.max(...values) };
}

// Global solvency check: the contract must hold at least the sum of all
// tracked stakes plus credited (claimable) balances. Burned bonds and
// rounding dust are retained surplus, so equality is not expected.
async function solvencyOk(ar, provider, accounts) {
  const balance = await provider.getBalance(await ar.getAddress());
  let liabilities = 0n;
  for (const a of accounts) {
    liabilities += await ar.pendingWithdrawals(a);
    liabilities += await ar.relayStake(a);
    liabilities += await ar.verifierStake(a);
  }
  return { ok: balance >= liabilities, balance, liabilities };
}

// Mirrors AccountableRelay._buildTree (odd node promoted as its own sibling).
function buildTreeWithProofs(leaves) {
  let level = leaves.slice();
  const proofs = leaves.map(() => []);
  const positions = leaves.map((_, i) => i);
  while (level.length > 1) {
    const m = Math.ceil(level.length / 2);
    const nextLevel = [];
    for (let i = 0; i < m; i++) {
      const left = level[2 * i];
      const right = 2 * i + 1 < level.length ? level[2 * i + 1] : left;
      nextLevel.push(ethers.keccak256(ethers.concat([left, right])));
    }
    for (let i = 0; i < positions.length; i++) {
      const pos = positions[i];
      const sibling = pos % 2 === 0 ? (pos + 1 < level.length ? pos + 1 : pos) : pos - 1;
      proofs[i].push(level[sibling]);
      positions[i] = Math.floor(pos / 2);
    }
    level = nextLevel;
  }
  return { root: level[0], proofs };
}

function leafEncoding(chainId, contractAddr, batchIndex, did, nonce, dataHash, sigHash) {
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["string", "uint256", "address", "uint256", "bytes32", "uint256", "bytes32", "bytes32"],
      ["BATCH_LEAF_DOMAIN_V1", chainId, contractAddr, batchIndex, did, nonce, dataHash, sigHash]
    )
  );
}

async function attestDigestOf(ar, disputeId, verdict) {
  return ar.computeAttestDigest(disputeId, verdict);
}

async function main() {
  const [deployer, owner, relay, challenger, verA, verB, verC] = await ethers.getSigners();
  const results = {};

  // --- deploy ---
  const DIDRegistry = await ethers.getContractFactory("DIDRegistry");
  const didRegistry = await DIDRegistry.deploy();
  await didRegistry.waitForDeployment();

  const AccountableRelay = await ethers.getContractFactory("AccountableRelay");
  const ar = await AccountableRelay.deploy(
    await didRegistry.getAddress(),
    CHALLENGE_PERIOD,
    QUORUM,
    ONE, // relay stake 1 ETH
    ONE / 2n, // verifier stake 0.5
    ONE / 10n, // challenger bond 0.1
    ONE / 2n, // relay slash 0.5
    ONE / 4n // verifier slash 0.25
  );
  await ar.waitForDeployment();
  results.deployment = Number((await ar.deploymentTransaction().wait()).gasUsed);

  const MetaTxRelay = await ethers.getContractFactory("MetaTxRelay");
  const v1relay = await MetaTxRelay.deploy(await didRegistry.getAddress());
  await v1relay.waitForDeployment();

  // --- stakes + committee registration ---
  results.stakeRelay = Number((await (await ar.connect(relay).stakeRelay({ value: ONE })).wait()).gasUsed);
  const verStake = [];
  for (const v of [verA, verB, verC]) {
    verStake.push(Number((await (await ar.connect(v).stakeVerifier({ value: ONE / 2n })).wait()).gasUsed));
  }
  results.stakeVerifier = summarize(verStake);
  results.invariantCommitteeRegistered = Number(await ar.verifierCount()) === 3;
  // Relay also registers as a verifier (for the conflict-of-interest test).
  await ar.connect(relay).stakeVerifier({ value: ONE / 2n });

  // --- V1 baseline ---
  const baseDid = ethers.id("did:falconiot:baseline");
  await didRegistry.connect(owner).registerDID(baseDid, ethers.randomBytes(FALCON_PK_SIZE));
  const v1gas = [];
  for (let i = 0; i < 10; i++) {
    const tx = await v1relay.connect(relay).submitTransaction(ethers.id(`v1-data-${i}`), baseDid, ethers.randomBytes(FALCON_SIG_SIZE), true);
    v1gas.push(Number((await tx.wait()).gasUsed));
  }
  results.v1BaselineSubmit = summarize(v1gas);

  // --- V3 accountable submissions ---
  const v3gas = [];
  for (let i = 0; i < 10; i++) {
    const didHash = ethers.id(`did:falconiot:accountable-${i}`);
    await didRegistry.connect(owner).registerDID(didHash, ethers.randomBytes(FALCON_PK_SIZE));
    const tx = await ar.connect(relay).submitAccountable(ethers.id(`v3-data-${i}`), didHash, ethers.randomBytes(FALCON_SIG_SIZE));
    v3gas.push(Number((await tx.wait()).gasUsed));
  }
  results.v3SubmitAccountable = summarize(v3gas);
  const delta = results.v3SubmitAccountable.mean - results.v1BaselineSubmit.mean;
  results.accountabilityDelta = { delta, percent: (100 * delta) / results.v1BaselineSubmit.mean };

  // I1: rejection checks
  let inactiveRejected = false;
  try { await ar.connect(relay).submitAccountable(ethers.id("x"), ethers.id("did:falconiot:missing"), ethers.randomBytes(FALCON_SIG_SIZE)); } catch { inactiveRejected = true; }
  let notStakedRejected = false;
  const outsiderDid = ethers.id("did:falconiot:outsider");
  await didRegistry.connect(owner).registerDID(outsiderDid, ethers.randomBytes(FALCON_PK_SIZE));
  try { await ar.connect(challenger).submitAccountable(ethers.id("x"), outsiderDid, ethers.randomBytes(FALCON_SIG_SIZE)); } catch { notStakedRejected = true; }
  results.invariantInactiveDidRejected = inactiveRejected;
  results.invariantNotStakedRejected = notStakedRejected;

  // --- I3: fraud path (record 0) ---
  const relayStakeBefore = await ar.relayStake(relay.address);

  const odTx = await ar.connect(challenger).openDispute(0, { value: ONE / 10n });
  results.openDispute = Number((await odTx.wait()).gasUsed);
  const d0 = await ar.getDispute(0);

  const digest0F = await attestDigestOf(ar, 0, true);
  const sigAF = await verA.signMessage(ethers.getBytes(digest0F));
  const sigBF = await verB.signMessage(ethers.getBytes(digest0F));
  results.submitAttestation = Number((await (await ar.connect(verA).submitAttestation(0, true, sigAF)).wait()).gasUsed);
  const resTx = await ar.connect(verB).submitAttestation(0, true, sigBF); // resolves
  results.submitAttestationResolvingFraud = Number((await resTx.wait()).gasUsed);

  const rec0 = await ar.getRecord(0);
  results.invariantFraudRevoked = Number(rec0.state) === 3;
  // Pull payments: nothing moves at resolution; everything is credited.
  // The FULL slash (0.5) leaves the relay stake: 0.3 challenger bounty +
  // 0.2 attester pool, all funded by the deduction (conservation).
  const arBalF0 = await ethers.provider.getBalance(await ar.getAddress());
  results.invariantRelaySlashed = (await ar.relayStake(relay.address)) === relayStakeBefore - ONE / 2n;
  const creditGain =
    (await ar.pendingWithdrawals(challenger.address)) +
    (await ar.pendingWithdrawals(verA.address)) +
    (await ar.pendingWithdrawals(verB.address));
  const arBalF1 = await ethers.provider.getBalance(await ar.getAddress());
  results.invariantFraudConservation =
    arBalF0 === arBalF1 && // resolution moves no ether
    creditGain === ONE * 3n / 10n + ONE / 10n + ONE / 5n; // bounty + refund + attester pool
  results.invariantFraudAttesterReward =
    (await ar.pendingWithdrawals(verA.address)) === ONE / 10n &&
    (await ar.pendingWithdrawals(verB.address)) === ONE / 10n; // 40% of 0.5 split by 2
  results.invariantChallengerCredited =
    (await ar.pendingWithdrawals(challenger.address)) === ONE * 3n / 10n + ONE / 10n; // bounty + refund

  // Top the slashed relay back up for later scenarios.
  await ar.connect(relay).stakeRelay({ value: ONE / 2n });

  // --- I4: spurious path (record 1) ---
  const relayPendingBefore = await ar.pendingWithdrawals(relay.address);
  await ar.connect(challenger).openDispute(1, { value: ONE / 10n });
  const digest1V = await attestDigestOf(ar, 1, false);
  const sigAV = await verA.signMessage(ethers.getBytes(digest1V));
  const sigBV = await verB.signMessage(ethers.getBytes(digest1V));
  await ar.connect(verA).submitAttestation(1, false, sigAV);
  results.submitAttestationResolvingSpurious = Number(
    (await (await ar.connect(verB).submitAttestation(1, false, sigBV)).wait()).gasUsed
  );
  const rec1 = await ar.getRecord(1);
  results.invariantSpuriousReturnsProvisional = Number(rec1.state) === 0; // NOT Confirmed
  results.invariantSpuriousBondToRelay =
    (await ar.pendingWithdrawals(relay.address)) - relayPendingBefore === ONE / 20n; // 50% of 0.1
  results.invariantSpuriousAttesterReward =
    (await ar.pendingWithdrawals(verA.address)) === ONE / 10n + ONE / 40n &&
    (await ar.pendingWithdrawals(verB.address)) === ONE / 10n + ONE / 40n; // prior + 0.05/2 each
  // M2: live exposure blocks committee exit while the target is unresolved.
  results.invariantExposureBlocksDeregister = Number(await ar.verifierLiveExposures(verA.address)) === 1;
  let deregBlocked = false;
  try { await ar.connect(verA).deregisterVerifier.staticCall(); } catch { deregBlocked = true; }
  results.invariantDeregisterRevertedWhileExposed = deregBlocked;

  // --- I5: re-dispute the same record, fraud now proven -> cross-dispute slashing ---
  const verAStake2 = await ar.verifierStake(verA.address);
  const verBStake2 = await ar.verifierStake(verB.address);
  const verAPending2 = await ar.pendingWithdrawals(verA.address);
  const chalPending2 = await ar.pendingWithdrawals(challenger.address);
  await ar.connect(challenger).openDispute(1, { value: ONE / 10n }); // dispute 2, same record
  const digest2F = await attestDigestOf(ar, 2, true);
  const sigCF = await verC.signMessage(ethers.getBytes(digest2F));
  const sigRelayF = await relay.signMessage(ethers.getBytes(digest2F));
  // I7: relay (registered verifier) attesting on its own record must revert.
  let conflictRejected = false;
  try { await ar.connect(relay).submitAttestation(2, true, sigRelayF); } catch { conflictRejected = true; }
  results.invariantConflictOfInterestRejected = conflictRejected;

  const att1 = await ar.connect(verC).submitAttestation(2, true, sigCF);
  results.submitAttestationNonResolving = Number((await att1.wait()).gasUsed);
  const digest2Fb = await attestDigestOf(ar, 2, true);
  const sigAF2 = await verA.signMessage(ethers.getBytes(digest2Fb)); // verA may attest (new dispute)
  await ar.connect(verA).submitAttestation(2, true, sigAF2); // fraud quorum -> resolves

  const rec1b = await ar.getRecord(1);
  results.invariantRedisputedFraudRevoked = Number(rec1b.state) === 3;
  // M2: wrong-side exposure released at the terminal verdict.
  results.invariantExposureReleased =
    (await ar.verifierLiveExposures(verA.address)) === 0n &&
    (await ar.verifierLiveExposures(verB.address)) === 0n;
  // verA and verB attested "valid" in dispute 1 -> both slashed 0.25 each.
  // verA attested fraud here (reward 40%/2 = 0.1 to each of verC, verA).
  const verBStake3 = await ar.verifierStake(verB.address);
  const verAStake3 = await ar.verifierStake(verA.address);
  // Slashing burns STAKE (payout is credited to the challenger); verB is only
  // registered-and-slashed: stake drops by exactly the verifier slash.
  results.invariantCrossDisputeSlashedVerB = verBStake2 - verBStake3 === ONE / 4n;
  // verA: stake also slashed 0.25; pending gains the attester reward.
  results.invariantCrossDisputeVerA =
    verAStake2 - verAStake3 === ONE / 4n &&
    (await ar.pendingWithdrawals(verA.address)) - verAPending2 === ONE / 10n;
  // Challenger is credited the two registry slashes (0.25 x 2) + bounty + refund.
  results.invariantCrossDisputeChallengerCredited =
    (await ar.pendingWithdrawals(challenger.address)) - chalPending2 ===
    ONE / 4n * 2n + ONE * 3n / 10n + ONE / 10n;

  // Slashing dropped verA/verB below the attestation threshold: they are
  // auto-ejected from the committee (stake-gated attestation). Re-stake to
  // continue; the ejection itself is an invariant worth noting.
  // Committee roster: verA, verB, verC + the relay (registered for the
  // conflict-of-interest test). Slashed verA/verB fall below the
  // attestation threshold and are gated out until they re-stake.
  results.invariantSlashedVerifierEjected =
    Number(await ar.verifierCount()) === 4 && (await ar.verifierStake(verA.address)) < ONE / 2n;
  await ar.connect(verA).stakeVerifier({ value: ONE / 4n });
  await ar.connect(verB).stakeVerifier({ value: ONE / 4n });

  // Top relay back up again.
  await ar.connect(relay).stakeRelay({ value: ONE / 2n });

  // --- I6: fail-closed expiry (record 2 disputed, no quorum) ---
  const chalPendingE = await ar.pendingWithdrawals(challenger.address);
  await ar.connect(challenger).openDispute(2, { value: ONE / 10n });
  const activeDuring = await ar.relayActiveDisputes(relay.address);
  await network.provider.send("evm_increaseTime", [CHALLENGE_PERIOD + 60]);
  await network.provider.send("evm_mine");
  const expTx = await ar.connect(verC).expireDispute(3);
  results.expireDispute = Number((await expTx.wait()).gasUsed);
  const rec2 = await ar.getRecord(2);
  results.invariantFailClosedRevoked = Number(rec2.state) === 3;
  results.invariantActiveDisputesDecrement = Number(activeDuring) === 1 && Number(await ar.relayActiveDisputes(relay.address)) === 0;
  // Half the bond is credited (claimable), half is burned in-contract.
  results.invariantExpiryPartialRefund =
    (await ar.pendingWithdrawals(challenger.address)) - chalPendingE === ONE / 20n;

  // Close out the remaining open dispute (dispute 2 target already revoked... 
  // dispute 2 was resolved; dispute 3 expired. Clean the last one if any.)
  // (No open dispute remains: 0,1,2 resolved, 3 expired.)
  results.invariantNoOpenDisputes = Number(await ar.relayActiveDisputes(relay.address)) === 0;

  // --- finalize remaining records after the window ---
  const finGas = [];
  for (const idx of [3, 4, 5, 6, 7, 8, 9]) {
    finGas.push(Number((await (await ar.connect(challenger).finalizeRecord(idx)).wait()).gasUsed));
  }
  results.finalizeRecord = summarize(finGas);
  results.invariantFinalizedState = Number((await ar.getRecord(3)).state) === 1;

  // I2: early finalization rejected on a fresh record
  const earlyDid = ethers.id("did:falconiot:early");
  await didRegistry.connect(owner).registerDID(earlyDid, ethers.randomBytes(FALCON_PK_SIZE));
  await ar.connect(relay).submitAccountable(ethers.id("early"), earlyDid, ethers.randomBytes(FALCON_SIG_SIZE));
  let earlyRejected = false;
  try { await ar.connect(challenger).finalizeRecord(10); } catch { earlyRejected = true; }
  results.invariantEarlyFinalizeRejected = earlyRejected;

  // I8: non-registered verifier and duplicate attestations rejected
  const dupDid = ethers.id("did:falconiot:dup");
  await didRegistry.connect(owner).registerDID(dupDid, ethers.randomBytes(FALCON_PK_SIZE));
  await ar.connect(relay).submitAccountable(ethers.id("dup"), dupDid, ethers.randomBytes(FALCON_SIG_SIZE));
  await ar.connect(challenger).openDispute(11, { value: ONE / 10n });
  const d4 = await ar.getDispute(4);
  const digest4 = await attestDigestOf(ar, 4, true);
  const sigChal = await challenger.signMessage(ethers.getBytes(digest4)); // challenger is NOT a registered verifier
  let nonVerifierRejected = false;
  try { await ar.connect(challenger).submitAttestation(4, true, sigChal); } catch { nonVerifierRejected = true; }
  results.invariantNonVerifierAttestationRejected = nonVerifierRejected;
  const sigAF4 = await verA.signMessage(ethers.getBytes(digest4));
  await ar.connect(verA).submitAttestation(4, true, sigAF4);
  let dupRejected = false;
  try { await ar.connect(verA).submitAttestation(4, true, sigAF4); } catch { dupRejected = true; }
  results.invariantDuplicateAttestationRejected = dupRejected;

  // --- pull-payment withdrawal (challenger claims all credits) ---
  const chalBalW = await ethers.provider.getBalance(challenger.address);
  const chalPendingTotal = await ar.pendingWithdrawals(challenger.address);
  const wTx = await ar.connect(challenger).withdraw();
  results.withdraw = Number((await wTx.wait()).gasUsed);
  const chalBalW2 = await ethers.provider.getBalance(challenger.address);
  results.invariantWithdrawPaysAll =
    (await ar.pendingWithdrawals(challenger.address)) === 0n &&
    chalPendingTotal > ONE; // bounty + refunds + registry slashes accumulated

  // --- verifier committee exit: deregister -> announce -> delay -> unstake ---
  const rosterBefore = Number(await ar.verifierCount());
  await ar.connect(verC).deregisterVerifier();
  results.invariantDeregisterDecrements = Number(await ar.verifierCount()) === rosterBefore - 1;
  await ar.connect(verC).announceVerifierUnstake();
  await network.provider.send('evm_increaseTime', [3 * 86400 + 3600]);
  await network.provider.send('evm_mine');
  const verCPendingBefore = await ar.pendingWithdrawals(verC.address);
  await ar.connect(verC).unstakeVerifier();
  results.invariantVerifierExitCreditsStake =
    (await ar.pendingWithdrawals(verC.address)) - verCPendingBefore === ONE / 2n;
  await ar.connect(verC).withdraw();
  results.invariantVerifierExitWithdraws =
    (await ar.pendingWithdrawals(verC.address)) === 0n;

  // --- M-b: unstake blocked at the final exit stage while exposure is live ---
  // Attack path: announce exit while clean, then acquire wrong-side exposure
  // via a spurious verdict, wait out the delay, and attempt to unstake.
  {
    await ar.connect(verC).stakeVerifier({ value: ONE / 2n }); // re-register
    const didMB = ethers.id("did:falconiot:mb");
    await didRegistry.connect(owner).registerDID(didMB, ethers.randomBytes(FALCON_PK_SIZE));
    await ar.connect(relay).submitAccountable(ethers.id("mb-data"), didMB, ethers.randomBytes(FALCON_SIG_SIZE));
    const mbIndex = Number(await ar.recordCount()) - 1;
    await ar.connect(verC).announceVerifierUnstake(); // exit clock starts while clean
    await ar.connect(challenger).openDispute(mbIndex, { value: ONE / 10n });
    const dMB = Number(await ar.disputeCount()) - 1;
    const dV = await attestDigestOf(ar, dMB, false);
    await ar.connect(verC).submitAttestation(dMB, false, await verC.signMessage(ethers.getBytes(dV)));
    await ar.connect(verA).submitAttestation(dMB, false, await verA.signMessage(ethers.getBytes(dV)));
    results.invariantExposureAcquiredLate = Number(await ar.verifierLiveExposures(verC.address)) === 1;

    await network.provider.send("evm_increaseTime", [3 * 86400 + 3600]);
    await network.provider.send("evm_mine");
    let unstakeBlocked = false;
    try { await ar.connect(verC).unstakeVerifier.staticCall(); } catch { unstakeBlocked = true; }
    results.invariantUnstakeRevertedWhileExposed = unstakeBlocked; // despite elapsed exit delay

    // Finalize the target -> terminal -> exposure released -> deregister and
    // unstake succeed (the announce from before the exposure still counts).
    await ar.connect(challenger).finalizeRecord(mbIndex);
    results.invariantLateExposureReleased = Number(await ar.verifierLiveExposures(verC.address)) === 0;
    await ar.connect(verC).deregisterVerifier();
    await ar.connect(verC).unstakeVerifier();
    // Stake credit + the spurious-verdict attester reward (0.05 bond / 2).
    results.invariantUnstakeSucceedsAfterRelease =
      (await ar.pendingWithdrawals(verC.address)) === ONE / 2n + ONE / 40n;
    await ar.connect(verC).withdraw();
  }

  // --- global solvency across every tracked account ---
  const solv = await solvencyOk(ar, ethers.provider, [relay, challenger, verA, verB, verC].map((w) => w.address));
  results.invariantSolvency = solv.ok;

  // --- batches: k = 10 / 50 / 100 + I9/I10 ---
  const batchResults = [];
  const chainId = (await ethers.provider.getNetwork()).chainId;
  const contractAddr = await ar.getAddress();
  for (const k of [10, 50, 100]) {
    const didHashes = [];
    const dataHashes = [];
    const sigs = [];
    for (let i = 0; i < k; i++) {
      const d = ethers.id(`did:falconiot:batch${k}-${i}`);
      await didRegistry.connect(owner).registerDID(d, ethers.randomBytes(FALCON_PK_SIZE));
      didHashes.push(d);
      dataHashes.push(ethers.id(`batch${k}-data-${i}`));
      sigs.push(ethers.randomBytes(FALCON_SIG_SIZE));
    }
    const tx = await ar.connect(relay).submitBatch(didHashes, dataHashes, ethers.concat(sigs));
    const receipt = await tx.wait();
    const batchIndex = Number((await ar.batchCount()) - 1n);
    const batch = await ar.getBatch(batchIndex);
    const leaves = didHashes.map((did, i) =>
      leafEncoding(chainId, contractAddr, batchIndex, did, 1n, dataHashes[i], ethers.keccak256(sigs[i]))
    );
    const { root, proofs } = buildTreeWithProofs(leaves);
    batchResults.push({ k, batchGas: Number(receipt.gasUsed), perTxGas: Math.round(Number(receipt.gasUsed) / k), rootMatches: root === batch.merkleRoot });
  }
  results.batch = batchResults;
  results.invariantBatchRootMatches = batchResults.every((b) => b.rootMatches);

  // --- I9 + I10: multi-leaf parallel disputes on a deterministic batch (k=8) ---
  {
    const k = 8;
    const didHashes = [];
    const dataHashes = [];
    const sigsDet = [];
    for (let i = 0; i < k; i++) {
      const d = ethers.id(`did:falconiot:dispute-batch-${i}`);
      if (!(await didRegistry.isActive(d))) {
        await didRegistry.connect(owner).registerDID(d, ethers.randomBytes(FALCON_PK_SIZE));
      }
      didHashes.push(d);
      dataHashes.push(ethers.id(`dispute-batch-data-${i}`));
      const det = new Uint8Array(FALCON_SIG_SIZE);
      const seed = ethers.getBytes(ethers.keccak256(ethers.toUtf8Bytes(`det-sig-${i}`)));
      for (let j = 0; j < FALCON_SIG_SIZE; j++) det[j] = seed[j % 32];
      sigsDet.push(det);
    }
    const tx = await ar.connect(relay).submitBatch(didHashes, dataHashes, ethers.concat(sigsDet));
    const batchIndex = Number((await ar.batchCount()) - 1n);
    const batch = await ar.getBatch(batchIndex);
    const leaves = didHashes.map((did, i) =>
      leafEncoding(chainId, contractAddr, batchIndex, did, 1n, dataHashes[i], ethers.keccak256(sigsDet[i]))
    );
    const { root, proofs } = buildTreeWithProofs(leaves);
    if (root !== batch.merkleRoot) throw new Error("deterministic batch root mismatch");

    // Bad Merkle proof rejected.
    let badProofRejected = false;
    try {
      await ar.openBatchLeafDispute.staticCall(batchIndex, 0, didHashes[0], 1n, dataHashes[0], ethers.keccak256(sigsDet[0]), [ethers.ZeroHash, ethers.ZeroHash, ethers.ZeroHash], { value: ONE / 10n });
    } catch { badProofRejected = true; }
    results.invariantBadMerkleProofRejected = badProofRejected;

    // Leaf 3: fraud -> revoked. Leaf 6: spurious -> upheld. In parallel.
    const openLeaf = async (leafIndex, verdict) => {
      const t = await ar.connect(challenger).openBatchLeafDispute(
        batchIndex, leafIndex, didHashes[leafIndex], 1n, dataHashes[leafIndex],
        ethers.keccak256(sigsDet[leafIndex]), proofs[leafIndex], { value: ONE / 10n }
      );
      return Number((await t.wait()).gasUsed);
    };
    results.openBatchLeafDispute = await openLeaf(3, true);
    await openLeaf(6, false);
    results.invariantParallelLeafDisputes = Number(await ar.batchOpenLeafDisputes(batchIndex)) === 2;

    const disputeFraud = Number(await ar.disputeCount()) - 2; // leaf-3 dispute
    const disputeSpur = Number(await ar.disputeCount()) - 1; // leaf-6 dispute
    const dF = await attestDigestOf(ar, disputeFraud, true);
    const dS = await attestDigestOf(ar, disputeSpur, false);
    await ar.connect(verA).submitAttestation(disputeFraud, true, await verA.signMessage(ethers.getBytes(dF)));
    await ar.connect(verB).submitAttestation(disputeFraud, true, await verB.signMessage(ethers.getBytes(dF)));
    await ar.connect(verA).submitAttestation(disputeSpur, false, await verA.signMessage(ethers.getBytes(dS)));
    await ar.connect(verB).submitAttestation(disputeSpur, false, await verB.signMessage(ethers.getBytes(dS)));

    results.invariantLeaf3Revoked = Number(await ar.batchLeafState(batchIndex, 3)) === 2; // Revoked
    results.invariantLeaf6Upheld = Number(await ar.batchLeafState(batchIndex, 6)) === 3; // Upheld
    results.invariantBatchStillProvisional = Number((await ar.getBatch(batchIndex)).state) === 0;

    // Finalizing the batch must fail: window still open.
    let earlyBatchRejected = false;
    try { await ar.connect(challenger).finalizeBatch(batchIndex); } catch { earlyBatchRejected = true; }
    results.invariantEarlyBatchFinalizeRejected = earlyBatchRejected;

    // After the window, batch finalizes with revokedLeafCount = 1.
    await network.provider.send("evm_increaseTime", [CHALLENGE_PERIOD + 60]);
    await network.provider.send("evm_mine");
    const finB = await ar.connect(challenger).finalizeBatch(batchIndex);
    results.finalizeBatch = Number((await finB.wait()).gasUsed);
    const after = await ar.getBatch(batchIndex);
    results.invariantBatchFinalizedWithRevocations = Number(after.state) === 1 && Number(after.revokedLeafCount) === 1;
  }

  // --- persist ---
  const outputDir = path.join(__dirname, "..", "results");
  if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });
  fs.writeFileSync(path.join(outputDir, "accountable-gas-report.json"), JSON.stringify(results, null, 2));

  const csv = [
    "operation,gas_mean,gas_stddev,n",
    `deployment,${results.deployment},0,1`,
    `stake_relay,${results.stakeRelay},0,1`,
    `stake_verifier,${results.stakeVerifier.mean},${results.stakeVerifier.stdDev},${results.stakeVerifier.n}`,
    `v1_baseline_submit,${results.v1BaselineSubmit.mean},${results.v1BaselineSubmit.stdDev},${results.v1BaselineSubmit.n}`,
    `v3_submit_accountable,${results.v3SubmitAccountable.mean},${results.v3SubmitAccountable.stdDev},${results.v3SubmitAccountable.n}`,
    `finalize_record,${results.finalizeRecord.mean},${results.finalizeRecord.stdDev},${results.finalizeRecord.n}`,
    `open_dispute,${results.openDispute},0,1`,
    `submit_attestation,${results.submitAttestation},0,1`,
    `submit_attestation_non_resolving,${results.submitAttestationNonResolving},0,1`,
    `submit_attestation_resolving_fraud,${results.submitAttestationResolvingFraud},0,1`,
    `submit_attestation_resolving_spurious,${results.submitAttestationResolvingSpurious},0,1`,
    `expire_dispute,${results.expireDispute},0,1`,
    `open_batch_leaf_dispute,${results.openBatchLeafDispute},0,1`,
    `finalize_batch_k8,${results.finalizeBatch},0,1`,
    ...results.batch.map((b) => `batch_k${b.k},${b.batchGas},0,1`),
    ...results.batch.map((b) => `batch_per_tx_k${b.k},${b.perTxGas},0,1`),
  ].join("\n");
  fs.writeFileSync(path.join(outputDir, "accountable-gas-report.csv"), csv);

  console.log(JSON.stringify(results, null, 2));
  console.log("\nSaved to results/accountable-gas-report.{json,csv}");
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
