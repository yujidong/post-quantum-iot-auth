// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "./DIDRegistry.sol";

/**
 * @title AccountableRelay
 * @notice V3 of the research prototype: accountable relaying with optimistic
 *         on-chain verification for post-quantum IoT authentication.
 *
 *         V3 hardens the adjudication mechanism of V2 against the attacks
 *         identified in internal review:
 *
 *         1. No challenge-window bypass. A "spurious dispute" resolution no
 *            longer confirms a record; it returns the record (or batch leaf)
 *            to the undecided state, so the full challenge window must
 *            elapse before finalization and disputes can be reopened with
 *            new evidence.
 *
 *         2. Cross-dispute wrong-side slashing. Every "valid" attestation
 *            ever cast on a target is registered; the first fraud verdict
 *            proven for that target slashes all of them. Colluding
 *            verifiers therefore remain punishable until the target is
 *            finalized, not only while their own dispute is open.
 *
 *         3. Verifier economics. Verifiers register in an explicit roster
 *            (q-of-n quorum), earn a share of the relay slash on fraud
 *            verdicts and a share of the challenger bond on spurious
 *            verdicts, and can exit after a delay. Attendance pays;
 *            non-attendance forfeits.
 *
 *         4. Anti-griefing fail-closed expiry. A dispute that expires
 *            without quorum revokes the target but refunds only half the
 *            challenger bond (the rest is burned), so disputing honest
 *            records costs real money even when no verdict forms.
 *
 *         5. Per-leaf batch disputability. Batch leaves can be disputed
 *            independently and in parallel; a batch finalizes only after
 *            its window closes and every open leaf dispute has resolved.
 *            Revoked leaves are tracked individually.
 *
 *         6. Hygiene. Reentrancy guard on resolution paths, conflict-of-
 *            interest ban (a target's endorsing relay cannot attest on its
 *            own disputes), and per-relay active-dispute counters instead
 *            of a boolean review flag.
 *
 * @dev Research prototype. Bond and bounty amounts are deployment
 *      parameters; the reference Hardhat benchmark uses the values listed
 *      in the paper's slashing schedule. Payouts follow
 *      checks-effects-interactions; the guard is defense in depth.
 */
contract AccountableRelay {
    // ------------------------------------------------------------------
    // Errors
    // ------------------------------------------------------------------
    error NotStakedRelay();
    error InactiveDID();
    error BadSignatureLength();
    error BadAvailabilityLength();
    error BatchLengthMismatch();
    error DuplicateAttestation();
    error NotVerifier();
    error NotRegisteredVerifier();
    error BadAttestation();
    error NothingToFinalize();
    error ChallengeWindowOpen();
    error NoDisputeOpen();
    error AlreadyResolved();
    error NothingToWithdraw();
    error BadMerkleProof();
    error UnknownDispute();
    error StillStaked();
    error ActiveDisputes();
    error InsufficientBond();
    error ConflictOfInterest();
    error LeafNotDisputable();
    error OpenLeafDisputes();
    error Reentrant();

    // ------------------------------------------------------------------
    // Types and storage
    // ------------------------------------------------------------------
    enum RecordState {
        Provisional, // inside the challenge window
        Confirmed, // window closed without a proven-fraud outcome
        Disputed, // an active dispute exists (single records)
        Revoked // fraud proven or fail-closed; excluded from the audit trail
    }

    enum LeafState {
        Undisputed, // inside the challenge window, never disputed
        Disputed, // an active dispute exists on this leaf
        Revoked, // fraud proven (or fail-closed expiry) on this leaf
        Upheld // a dispute resolved spurious; disputable again
    }

    struct Record {
        bytes32 dataHash; // h(m): IoT payload commitment
        bytes32 didHash; // device DID
        bytes falconSignature; // raw Falcon-512 signature (offline re-verification)
        bytes32 pubKeyHash; // DID-anchored key snapshot
        uint64 submittedAt;
        address relay; // ATTRIBUTABLE submitter
        uint256 nonce; // per-DID sequence number assigned on-chain
        RecordState state;
    }

    struct Batch {
        bytes32 merkleRoot; // root of the bound-leaf tree (contract-built)
        uint256 leafCount;
        bytes32 availabilityCommitment; // keccak256 over concatenated raw signatures
        uint64 submittedAt;
        address relay;
        uint256 revokedLeafCount; // leaves revoked by fraud/expiry verdicts
        RecordState state; // Provisional until finalized (leaf states tracked separately)
    }

    struct Dispute {
        uint8 targetType; // 0 = single record, 1 = batch leaf
        uint256 targetIndex; // record index or batch index
        uint256 leafIndex; // batch leaf (targetType == 1)
        address challenger;
        uint256 bond;
        uint64 openedAt;
        uint64 deadline;
        address[] fraudAttesters; // verifiers voting "signature invalid"
        address[] validAttesters; // verifiers voting "signature valid"
        bool resolved;
    }

    DIDRegistry public immutable didRegistry;
    uint64 public immutable challengePeriod;
    uint256 public immutable quorum;

    // Accountability economics (deployment parameters; reference values in
    // the paper's slashing schedule: 1 / 0.5 / 0.1 / 0.5 / 0.25 ETH).
    uint256 public immutable relayStakeAmount;
    uint256 public immutable verifierStakeAmount;
    uint256 public immutable challengerBondAmount;
    uint256 public immutable relaySlashAmount;
    uint256 public immutable verifierSlashAmount;
    uint256 public constant UNSTAKE_DELAY = 3 days;

    uint256 public constant FALCON_512_SIG_SIZE_MAX = 752;

    mapping(address => uint256) public relayStake;
    mapping(address => uint256) public relayExitTime;
    mapping(address => uint256) public relayActiveDisputes; // open disputes naming this relay

    // Verifier committee roster (explicit n; quorum is q of n).
    mapping(address => uint256) public verifierStake;
    mapping(address => bool) public isRegisteredVerifier;
    mapping(address => uint256) public verifierExitTime;
    address[] private _verifierRoster;
    uint256 public verifierCount;

    mapping(bytes32 => uint256) public didNonce; // per-DID sequence numbers

    Record[] private records;
    Batch[] private batches;
    Dispute[] private disputes;

    // Batch leaf states and open-dispute accounting.
    mapping(uint256 => mapping(uint256 => LeafState)) public batchLeafState;
    mapping(uint256 => uint256) public batchOpenLeafDisputes;

    // Cross-dispute registry of "valid" attestations per target: the first
    // fraud verdict for a target slashes every listed verifier.
    mapping(bytes32 => address[]) private _targetValidList;
    mapping(bytes32 => mapping(address => bool)) private _targetValidHas;

    mapping(uint256 => mapping(address => bool)) private _hasAttested;

    // Pull-payment ledger: all resolution payouts, refunds, and unstakes are
    // credited here and claimed via withdraw(), so no resolution can be
    // blocked by a recipient contract whose fallback reverts.
    mapping(address => uint256) public pendingWithdrawals;

    // Live wrong-side exposure: incremented when a verifier's ``valid''
    // attestation is registered on an un-finalized target, released when the
    // target reaches a terminal state (finalized, revoked by fraud, or
    // revoked by fail-closed expiry). A verifier with live exposure cannot
    // leave the roster or announce an exit, making ``punishable until
    // finalization'' a code guarantee rather than a timing assumption.
    mapping(address => uint256) public verifierLiveExposures;
    // Batch leaves whose dispute registries are non-empty (for release at
    // batch finalization without iterating every leaf).
    mapping(uint256 => uint256[]) private _exposedLeaves;

    uint256 private _guard = 1;

    // ------------------------------------------------------------------
    // Events
    // ------------------------------------------------------------------
    event RelayStaked(address indexed relay, uint256 amount);
    event RelayUnstaked(address indexed relay, uint256 amount);
    event VerifierRegistered(address indexed verifier);
    event VerifierUnstaked(address indexed verifier, uint256 amount);
    event RecordSubmitted(
        uint256 indexed index, bytes32 indexed didHash, uint256 nonce, bytes32 dataHash, address indexed relay
    );
    event RecordFinalized(uint256 indexed index);
    event BatchSubmitted(
        uint256 indexed batchIndex,
        bytes32 merkleRoot,
        uint256 leafCount,
        bytes32 availabilityCommitment,
        address indexed relay
    );
    event BatchLeaf(
        uint256 indexed batchIndex, uint256 indexed leafIndex, bytes32 indexed didHash, uint256 nonce, bytes32 dataHash, bytes32 sigHash
    );
    event BatchFinalized(uint256 indexed batchIndex, uint256 revokedLeafCount);
    event DisputeOpened(uint256 indexed disputeId, uint8 targetType, uint256 targetIndex, address challenger);
    event DisputeResolved(uint256 indexed disputeId, bool fraudProven);
    event DisputeExpired(uint256 indexed disputeId);
    event LeafRevoked(uint256 indexed batchIndex, uint256 indexed leafIndex);
    event VerifierDeregistered(address indexed verifier);
    event Withdrawn(address indexed account, uint256 amount);

    modifier nonReentrant() {
        if (_guard != 1) revert Reentrant();
        _guard = 2;
        _;
        _guard = 1;
    }

    // ------------------------------------------------------------------
    // Construction
    // ------------------------------------------------------------------
    constructor(
        address _didRegistry,
        uint64 _challengePeriod,
        uint256 _quorum,
        uint256 _relayStake,
        uint256 _verifierStake,
        uint256 _challengerBond,
        uint256 _relaySlash,
        uint256 _verifierSlash
    ) {
        didRegistry = DIDRegistry(_didRegistry);
        challengePeriod = _challengePeriod;
        quorum = _quorum;
        relayStakeAmount = _relayStake;
        verifierStakeAmount = _verifierStake;
        challengerBondAmount = _challengerBond;
        relaySlashAmount = _relaySlash;
        verifierSlashAmount = _verifierSlash;
    }

    // ------------------------------------------------------------------
    // Stake and committee management
    // ------------------------------------------------------------------
    function stakeRelay() external payable {
        if (msg.value == 0) revert NotStakedRelay();
        relayStake[msg.sender] += msg.value;
        emit RelayStaked(msg.sender, msg.value);
    }

    function announceUnstake() external {
        if (relayStake[msg.sender] == 0) revert NotStakedRelay();
        if (relayActiveDisputes[msg.sender] != 0) revert ActiveDisputes();
        relayExitTime[msg.sender] = block.timestamp + UNSTAKE_DELAY;
    }

    function unstakeRelay() external nonReentrant {
        uint256 amount = relayStake[msg.sender];
        if (amount == 0) revert NotStakedRelay();
        if (relayActiveDisputes[msg.sender] != 0) revert ActiveDisputes();
        if (relayExitTime[msg.sender] == 0 || block.timestamp < relayExitTime[msg.sender]) revert StillStaked();
        relayStake[msg.sender] = 0;
        relayExitTime[msg.sender] = 0;
        _credit(msg.sender, amount);
        emit RelayUnstaked(msg.sender, amount);
    }

    function stakeVerifier() external payable {
        if (msg.value == 0) revert NotVerifier();
        verifierStake[msg.sender] += msg.value;
        if (!isRegisteredVerifier[msg.sender] && verifierStake[msg.sender] >= verifierStakeAmount) {
            isRegisteredVerifier[msg.sender] = true;
            _verifierRoster.push(msg.sender);
            verifierCount += 1;
            emit VerifierRegistered(msg.sender);
        }
    }

    function announceVerifierUnstake() external {
        if (verifierStake[msg.sender] == 0) revert NotVerifier();
        if (verifierLiveExposures[msg.sender] != 0) revert ActiveDisputes();
        verifierExitTime[msg.sender] = block.timestamp + UNSTAKE_DELAY;
    }

    function unstakeVerifier() external nonReentrant {
        uint256 amount = verifierStake[msg.sender];
        if (amount == 0) revert NotVerifier();
        if (isRegisteredVerifier[msg.sender]) revert StillStaked(); // deregister first
        if (verifierLiveExposures[msg.sender] != 0) revert ActiveDisputes(); // exit blocked at every stage
        if (verifierExitTime[msg.sender] == 0 || block.timestamp < verifierExitTime[msg.sender]) revert StillStaked();
        verifierStake[msg.sender] = 0;
        verifierExitTime[msg.sender] = 0;
        _credit(msg.sender, amount);
        emit VerifierUnstaked(msg.sender, amount);
    }

    /**
     * @notice Leave the committee roster. Required before unstaking; the
     *         delayed unstake still applies afterwards.
     */
    function deregisterVerifier() external {
        if (!isRegisteredVerifier[msg.sender]) revert NotRegisteredVerifier();
        if (verifierLiveExposures[msg.sender] != 0) revert ActiveDisputes();
        isRegisteredVerifier[msg.sender] = false;
        uint256 n = _verifierRoster.length;
        for (uint256 i = 0; i < n; i++) {
            if (_verifierRoster[i] == msg.sender) {
                _verifierRoster[i] = _verifierRoster[n - 1];
                _verifierRoster.pop();
                verifierCount -= 1;
                break;
            }
        }
        emit VerifierDeregistered(msg.sender);
    }

    function verifierRoster(uint256 i) external view returns (address) {
        return _verifierRoster[i];
    }

    // ------------------------------------------------------------------
    // Accountable single-record submission
    // ------------------------------------------------------------------
    function submitAccountable(bytes32 dataHash, bytes32 didHash, bytes calldata falconSignature)
        external
        returns (uint256 index)
    {
        if (relayStake[msg.sender] < relayStakeAmount) revert NotStakedRelay();
        if (!didRegistry.isActive(didHash)) revert InactiveDID();
        if (falconSignature.length == 0 || falconSignature.length > FALCON_512_SIG_SIZE_MAX) {
            revert BadSignatureLength();
        }

        // Context binding: the on-chain-assigned nonce makes each recorded
        // (DID, payload, signature) consumption a unique, ordered event; the
        // record fields themselves are the commitment.
        uint256 nonce = ++didNonce[didHash];

        bytes memory pubKey = didRegistry.getPublicKey(didHash);

        index = records.length;
        records.push(
            Record({
                dataHash: dataHash,
                didHash: didHash,
                falconSignature: falconSignature,
                pubKeyHash: keccak256(pubKey),
                submittedAt: uint64(block.timestamp),
                relay: msg.sender,
                nonce: nonce,
                state: RecordState.Provisional
            })
        );

        emit RecordSubmitted(index, didHash, nonce, dataHash, msg.sender);
    }

    // ------------------------------------------------------------------
    // Permissionless finalization after the challenge window
    // ------------------------------------------------------------------
    function finalizeRecord(uint256 index) external {
        Record storage r = records[index];
        if (r.state != RecordState.Provisional) revert NothingToFinalize();
        if (block.timestamp < r.submittedAt + challengePeriod) revert ChallengeWindowOpen();
        r.state = RecordState.Confirmed;
        _releaseExposures(keccak256(abi.encodePacked(uint8(0), index, uint256(0))));
        emit RecordFinalized(index);
    }

    // ------------------------------------------------------------------
    // Accountable batch submission with bound Merkle leaves
    // ------------------------------------------------------------------
    function submitBatch(bytes32[] calldata didHashes, bytes32[] calldata dataHashes, bytes calldata availabilityData)
        external
        returns (uint256 batchIndex, bytes32 root)
    {
        if (relayStake[msg.sender] < relayStakeAmount) revert NotStakedRelay();
        uint256 k = didHashes.length;
        if (k == 0 || dataHashes.length != k) revert BatchLengthMismatch();
        if (availabilityData.length != k * FALCON_512_SIG_SIZE_MAX) revert BadAvailabilityLength();

        batchIndex = batches.length;
        bytes32[] memory leaves = new bytes32[](k);

        for (uint256 i = 0; i < k; i++) {
            _processLeaf(batchIndex, i, didHashes[i], dataHashes[i], availabilityData, leaves);
        }

        root = _buildTree(leaves);

        batches.push(
            Batch({
                merkleRoot: root,
                leafCount: k,
                availabilityCommitment: keccak256(availabilityData),
                submittedAt: uint64(block.timestamp),
                relay: msg.sender,
                revokedLeafCount: 0,
                state: RecordState.Provisional
            })
        );

        emit BatchSubmitted(batchIndex, root, k, keccak256(availabilityData), msg.sender);
    }

    function finalizeBatch(uint256 batchIndex) external {
        Batch storage b = batches[batchIndex];
        if (b.state != RecordState.Provisional) revert NothingToFinalize();
        if (block.timestamp < b.submittedAt + challengePeriod) revert ChallengeWindowOpen();
        if (batchOpenLeafDisputes[batchIndex] != 0) revert OpenLeafDisputes();
        b.state = RecordState.Confirmed;
        uint256[] storage exposed = _exposedLeaves[batchIndex];
        for (uint256 i = 0; i < exposed.length; i++) {
            _releaseExposures(keccak256(abi.encodePacked(uint8(1), batchIndex, exposed[i])));
        }
        delete _exposedLeaves[batchIndex];
        emit BatchFinalized(batchIndex, b.revokedLeafCount);
    }

    // ------------------------------------------------------------------
    // Disputes
    // ------------------------------------------------------------------
    function openDispute(uint256 recordIndex) external payable returns (uint256 disputeId) {
        if (msg.value < challengerBondAmount) revert InsufficientBond();
        Record storage r = records[recordIndex];
        if (r.state != RecordState.Provisional) revert NothingToFinalize();
        r.state = RecordState.Disputed;
        relayActiveDisputes[r.relay] += 1;
        disputeId = _openDispute(0, recordIndex, 0);
    }

    function openBatchLeafDispute(
        uint256 batchIndex,
        uint256 leafIndex,
        bytes32 didHash,
        uint256 nonce,
        bytes32 dataHash,
        bytes32 sigHash,
        bytes32[] calldata merkleProof
    ) external payable returns (uint256 disputeId) {
        if (msg.value < challengerBondAmount) revert InsufficientBond();
        Batch storage b = batches[batchIndex];
        if (b.state != RecordState.Provisional) revert NothingToFinalize();
        if (leafIndex >= b.leafCount) revert BadMerkleProof();
        LeafState ls = batchLeafState[batchIndex][leafIndex];
        if (ls == LeafState.Disputed || ls == LeafState.Revoked) revert LeafNotDisputable();

        bytes32 leaf = _leafHash(batchIndex, didHash, nonce, dataHash, sigHash);
        if (!_verifyProof(leaf, merkleProof, leafIndex, b.merkleRoot)) revert BadMerkleProof();

        batchLeafState[batchIndex][leafIndex] = LeafState.Disputed;
        batchOpenLeafDisputes[batchIndex] += 1;
        relayActiveDisputes[b.relay] += 1;
        disputeId = _openDispute(1, batchIndex, leafIndex);
    }

    function _openDispute(uint8 targetType, uint256 targetIndex, uint256 leafIndex) internal returns (uint256) {
        disputes.push();
        Dispute storage d = disputes[disputes.length - 1];
        d.targetType = targetType;
        d.targetIndex = targetIndex;
        d.leafIndex = leafIndex;
        d.challenger = msg.sender;
        d.bond = msg.value;
        d.openedAt = uint64(block.timestamp);
        d.deadline = uint64(block.timestamp) + challengePeriod;
        emit DisputeOpened(disputes.length - 1, targetType, targetIndex, msg.sender);
        return disputes.length - 1;
    }

    /**
     * @notice Submit a committee attestation for an open dispute. The
     *         signature must come from a registered, staked verifier that
     *         is not the target's endorsing relay (conflict of interest).
     */
    function submitAttestation(uint256 disputeId, bool verdictIsFraud, bytes calldata signature) external nonReentrant {
        Dispute storage d = disputes[disputeId];
        if (d.deadline == 0) revert UnknownDispute();
        if (d.resolved || block.timestamp > d.deadline) revert NoDisputeOpen();

        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", _attestInner(disputeId, verdictIsFraud)));
        address signer = _recover(digest, signature);
        if (!isRegisteredVerifier[signer] || verifierStake[signer] < verifierStakeAmount) revert NotRegisteredVerifier();
        if (signer == _targetRelay(d)) revert ConflictOfInterest();
        if (_hasAttested[disputeId][signer]) revert DuplicateAttestation();
        _hasAttested[disputeId][signer] = true;

        if (verdictIsFraud) {
            d.fraudAttesters.push(signer);
        } else {
            d.validAttesters.push(signer);
        }

        if (d.fraudAttesters.length >= quorum) {
            _resolveFraud(disputeId);
        } else if (d.validAttesters.length >= quorum) {
            _resolveSpurious(disputeId);
        }
    }

    /**
     * @notice Fail-closed expiry: a dispute that reaches its deadline
     *         without a quorum revokes the target, refunds half the
     *         challenger bond, and burns the remainder (retained by the
     *         contract), so disputing honest records has a real cost.
     */
    function expireDispute(uint256 disputeId) external nonReentrant {
        Dispute storage d = disputes[disputeId];
        if (d.deadline == 0) revert UnknownDispute();
        if (d.resolved) revert AlreadyResolved();
        if (block.timestamp <= d.deadline) revert ChallengeWindowOpen();

        d.resolved = true;
        _revokeTarget(d);
        _closeDispute(d);
        _releaseExposures(_targetKey(d)); // terminal: release wrong-side stakes

        // Half the bond is refunded (claimable); the rest is burned
        // (retained by the contract).
        _credit(d.challenger, d.bond / 2);

        emit DisputeExpired(disputeId);
    }

    // ------------------------------------------------------------------
    // Resolution, rewards, and slashing
    // ------------------------------------------------------------------

    function _targetRelay(Dispute storage d) internal view returns (address) {
        return d.targetType == 0 ? records[d.targetIndex].relay : batches[d.targetIndex].relay;
    }

    function _targetKey(Dispute storage d) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(d.targetType, d.targetIndex, d.leafIndex));
    }

    /**
     * @dev Fraud proven: revoke the target, slash the relay (60% challenger
     *      bounty, 40% shared by the fraud attesters), refund the
     *      challenger, and slash EVERY verifier that ever attested "valid"
     *      on this target across all of its disputes.
     */
    function _resolveFraud(uint256 disputeId) internal {
        Dispute storage d = disputes[disputeId];
        d.resolved = true;
        _revokeTarget(d);
        _closeDispute(d);

        // Register this dispute's valid attesters, then slash all wrong-side
        // verifiers ever recorded for the target.
        bytes32 key = _targetKey(d);
        for (uint256 i = 0; i < d.validAttesters.length; i++) {
            _registerValidAtt(key, d.validAttesters[i]);
        }
        if (d.targetType == 1) _rememberExposedLeaf(d.targetIndex, d.leafIndex);
        address payable challenger = payable(d.challenger);
        address[] storage wrongSide = _targetValidList[key];
        for (uint256 i = 0; i < wrongSide.length; i++) {
            _slashFromPool(wrongSide[i], verifierSlashAmount, challenger, true);
        }
        _releaseExposures(key); // target is terminal: wrong-side stakes can no longer be slashed

        // The FULL relay slash is deducted from the relay's stake first
        // (with pool fallback), then split: 60% challenger bounty, 40%
        // attester pool. Rounding dust is retained by the contract, so every
        // credited wei is backed by a deducted wei (conservation).
        uint256 collected = _collectFromPool(_targetRelay(d), relaySlashAmount, false);
        _credit(challenger, collected * 3 / 5);
        _payAttesters(d.fraudAttesters, collected * 2 / 5);

        _credit(d.challenger, d.bond);

        emit DisputeResolved(disputeId, true);
    }

    /**
     * @dev Spurious dispute: the target returns to the UNDECIDED state (the
     *      challenge window is not bypassed and the dispute can be reopened
     *      with new evidence). The bond compensates the relay (50%) and the
     *      attesters who showed up (50%). The valid attesters are registered
     *      and remain slashable if fraud is ever proven for this target.
     */
    function _resolveSpurious(uint256 disputeId) internal {
        Dispute storage d = disputes[disputeId];
        d.resolved = true;

        if (d.targetType == 0) {
            records[d.targetIndex].state = RecordState.Provisional; // NOT Confirmed
        } else {
            batchLeafState[d.targetIndex][d.leafIndex] = LeafState.Upheld; // disputable again
        }
        _closeDispute(d);

        // Register valid attesters for future cross-dispute slashing.
        bytes32 key = _targetKey(d);
        for (uint256 i = 0; i < d.validAttesters.length; i++) {
            _registerValidAtt(key, d.validAttesters[i]);
        }
        if (d.targetType == 1) _rememberExposedLeaf(d.targetIndex, d.leafIndex);

        _payAttesters(d.validAttesters, d.bond / 2); // attester reward: 50% of bond
        _credit(_targetRelay(d), d.bond - d.bond / 2); // relay compensation: 50%

        emit DisputeResolved(disputeId, false);
    }

    function _revokeTarget(Dispute storage d) internal {
        if (d.targetType == 0) {
            records[d.targetIndex].state = RecordState.Revoked;
        } else {
            if (batchLeafState[d.targetIndex][d.leafIndex] != LeafState.Revoked) {
                batchLeafState[d.targetIndex][d.leafIndex] = LeafState.Revoked;
                batches[d.targetIndex].revokedLeafCount += 1;
                emit LeafRevoked(d.targetIndex, d.leafIndex);
            }
        }
    }

    function _closeDispute(Dispute storage d) internal {
        relayActiveDisputes[_targetRelay(d)] -= 1;
        if (d.targetType == 1) {
            batchOpenLeafDisputes[d.targetIndex] -= 1;
        }
    }

    function _registerValidAtt(bytes32 key, address v) internal {
        if (!_targetValidHas[key][v]) {
            _targetValidHas[key][v] = true;
            _targetValidList[key].push(v);
            verifierLiveExposures[v] += 1;
        }
    }

    /**
     * @dev Release live-exposure counters for a target that reached a
     *      terminal state (its wrong-side attestations can no longer be
     *      slashed). Called from finalization, fraud resolution, and
     *      fail-closed expiry.
     */
    function _releaseExposures(bytes32 key) internal {
        address[] storage list = _targetValidList[key];
        for (uint256 i = 0; i < list.length; i++) {
            verifierLiveExposures[list[i]] -= 1;
        }
        delete _targetValidList[key]; // entries imply _targetValidHas; the outer map is never re-used for a released key
    }

    function _rememberExposedLeaf(uint256 batchIndex, uint256 leafIndex) internal {
        uint256[] storage leaves = _exposedLeaves[batchIndex];
        for (uint256 i = 0; i < leaves.length; i++) {
            if (leaves[i] == leafIndex) return;
        }
        leaves.push(leafIndex);
    }

    function _payAttesters(address[] storage attesters, uint256 total) internal {
        if (attesters.length == 0 || total == 0) return;
        uint256 share = total / attesters.length;
        for (uint256 i = 0; i < attesters.length; i++) {
            _credit(attesters[i], share);
        }
    }

    /**
     * @dev Deduct `amount` from the specified stake pool of `from` (relay
     *      pool when `fromVerifierPool` is false, verifier pool otherwise),
     *      falling back to the other pool. Returns the amount actually
     *      deducted (bounded by the available stakes).
     */
    function _collectFromPool(address from, uint256 amount, bool fromVerifierPool) internal returns (uint256 deducted) {
        if (fromVerifierPool) {
            uint256 vStake = verifierStake[from];
            uint256 take = vStake < amount ? vStake : amount;
            verifierStake[from] = vStake - take;
            unchecked { amount -= take; }
            deducted += take;
            if (amount > 0) {
                uint256 rStake = relayStake[from];
                take = rStake < amount ? rStake : amount;
                relayStake[from] = rStake - take;
                deducted += take;
            }
        } else {
            uint256 rStake = relayStake[from];
            uint256 take = rStake < amount ? rStake : amount;
            relayStake[from] = rStake - take;
            unchecked { amount -= take; }
            deducted += take;
            if (amount > 0) {
                uint256 vStake = verifierStake[from];
                take = vStake < amount ? vStake : amount;
                verifierStake[from] = vStake - take;
                deducted += take;
            }
        }
    }

    /**
     * @dev Slash `amount` from the specified stake pool of `from` and credit
     *      it to `to`; shortfalls fall through to the other pool.
     */
    function _slashFromPool(address from, uint256 amount, address payable to, bool fromVerifierPool) internal {
        uint256 deducted = _collectFromPool(from, amount, fromVerifierPool);
        if (deducted > 0) {
            _credit(to, deducted);
        }
    }

    /**
     * @dev Credit a pull-payment. Funds never move during dispute resolution.
     */
    function _credit(address to, uint256 amount) internal {
        if (amount > 0) pendingWithdrawals[to] += amount;
    }

    /**
     * @notice Claim all credited payouts, refunds, and unstaked balances.
     */
    function withdraw() external nonReentrant {
        uint256 amount = pendingWithdrawals[msg.sender];
        if (amount == 0) revert NothingToWithdraw();
        pendingWithdrawals[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "withdraw transfer failed");
        emit Withdrawn(msg.sender, amount);
    }

    // ------------------------------------------------------------------
    // Views
    // ------------------------------------------------------------------
    function recordCount() external view returns (uint256) {
        return records.length;
    }

    function batchCount() external view returns (uint256) {
        return batches.length;
    }

    function disputeCount() external view returns (uint256) {
        return disputes.length;
    }

    function getRecord(uint256 index)
        external
        view
        returns (
            bytes32 dataHash,
            bytes32 didHash,
            bytes memory falconSignature,
            bytes32 pubKeyHash,
            uint64 submittedAt,
            address relay,
            uint256 nonce,
            RecordState state
        )
    {
        Record storage r = records[index];
        return (r.dataHash, r.didHash, r.falconSignature, r.pubKeyHash, r.submittedAt, r.relay, r.nonce, r.state);
    }

    function getBatch(uint256 batchIndex)
        external
        view
        returns (
            bytes32 merkleRoot,
            uint256 leafCount,
            bytes32 availabilityCommitment,
            address relay,
            uint256 revokedLeafCount,
            RecordState state
        )
    {
        Batch storage b = batches[batchIndex];
        return (b.merkleRoot, b.leafCount, b.availabilityCommitment, b.relay, b.revokedLeafCount, b.state);
    }

    function getDispute(uint256 disputeId)
        external
        view
        returns (uint8 targetType, uint256 targetIndex, uint256 leafIndex, address challenger, uint256 bond, bool resolved)
    {
        Dispute storage d = disputes[disputeId];
        return (d.targetType, d.targetIndex, d.leafIndex, d.challenger, d.bond, d.resolved);
    }

    // ------------------------------------------------------------------
    // Cryptographic helpers
    // ------------------------------------------------------------------
    function _attestInner(uint256 disputeId, bool verdictIsFraud) internal view returns (bytes32) {
        Dispute storage d = disputes[disputeId];
        return keccak256(
            abi.encode("ATTEST_DOMAIN_V1", disputeId, verdictIsFraud, d.targetType, d.targetIndex, d.leafIndex)
        );
    }

    /**
     * @notice The domain-separated digest that a committee verifier signs
     *         with a standard personal_sign (EIP-191) operation.
     */
    function computeAttestDigest(uint256 disputeId, bool verdictIsFraud) external view returns (bytes32) {
        return _attestInner(disputeId, verdictIsFraud);
    }

    function _recover(bytes32 digest, bytes calldata signature) internal pure returns (address) {
        if (signature.length != 65) revert BadAttestation();
        bytes32 r = bytes32(signature[0:32]);
        bytes32 s = bytes32(signature[32:64]);
        uint8 v = uint8(signature[64]);
        if (v < 27) v += 27;
        address signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) revert BadAttestation();
        return signer;
    }

    function _processLeaf(
        uint256 batchIndex,
        uint256 i,
        bytes32 didHash,
        bytes32 dataHash,
        bytes calldata availabilityData,
        bytes32[] memory leaves
    ) internal {
        if (!didRegistry.isActive(didHash)) revert InactiveDID();
        uint256 nonce = ++didNonce[didHash];
        bytes32 sigHash = _sliceHash(availabilityData, i * FALCON_512_SIG_SIZE_MAX);
        leaves[i] = _leafHash(batchIndex, didHash, nonce, dataHash, sigHash);
        emit BatchLeaf(batchIndex, i, didHash, nonce, dataHash, sigHash);
    }

    function _sliceHash(bytes calldata data, uint256 offset) internal pure returns (bytes32 h) {
        return keccak256(data[offset:offset + FALCON_512_SIG_SIZE_MAX]);
    }

    function _leafHash(uint256 batchIndex, bytes32 didHash, uint256 nonce, bytes32 dataHash, bytes32 sigHash)
        internal
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encode("BATCH_LEAF_DOMAIN_V1", block.chainid, address(this), batchIndex, didHash, nonce, dataHash, sigHash)
        );
    }

    // ------------------------------------------------------------------
    // Merkle tree (binary, odd nodes promoted; contract-built)
    // ------------------------------------------------------------------
    function _buildTree(bytes32[] memory leaves) internal pure returns (bytes32 root) {
        uint256 n = leaves.length;
        if (n == 1) return leaves[0];
        while (n > 1) {
            uint256 m = (n + 1) / 2;
            for (uint256 i = 0; i < m; i++) {
                bytes32 left = leaves[2 * i];
                bytes32 right = (2 * i + 1 < n) ? leaves[2 * i + 1] : leaves[2 * i];
                leaves[i] = keccak256(abi.encodePacked(left, right));
            }
            n = m;
        }
        return leaves[0];
    }

    function _verifyProof(bytes32 leaf, bytes32[] calldata proof, uint256 index, bytes32 root)
        internal
        pure
        returns (bool)
    {
        bytes32 h = leaf;
        uint256 idx = index;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 p = proof[i];
            if (idx % 2 == 0) {
                h = keccak256(abi.encodePacked(h, p));
            } else {
                h = keccak256(abi.encodePacked(p, h));
            }
            idx /= 2;
        }
        return h == root;
    }
}
