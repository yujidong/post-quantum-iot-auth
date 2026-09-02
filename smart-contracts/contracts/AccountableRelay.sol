// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "./DIDRegistry.sol";

/**
 * @title AccountableRelay
 * @notice V2 of the MetaTxRelay research prototype: accountable relaying
 *         with optimistic on-chain verification for post-quantum IoT
 *         authentication.
 *
 *         Motivation (reviewer-driven redesign): in V1 the smart contract
 *         stored whatever the relay claimed, the submitting relay was not
 *         even recorded per transaction, and replay protection did not
 *         bind signatures to a DID/nonce/chain context. A compromised
 *         (or quantum-forged) relay ECDSA key could therefore commit
 *         arbitrary payloads as "verified" records.
 *
 *         V2 closes this gap with four mechanisms:
 *
 *         1. Attributable endorsement. Only a staked relay may submit;
 *            every record permanently names its submitting relay, so
 *            misbehaviour is attributable and economically punishable.
 *
 *         2. Context binding. Each submission consumes a per-DID nonce
 *            assigned on-chain and the anti-replay commitment domain-
 *            separates (DID, nonce, data hash, signature hash, chain id,
 *            contract address). Batch leaves bind the same tuple into the
 *            Merkle root, which the contract constructs itself from the
 *            submitted calldata.
 *
 *         3. Optimistic verification. Records land on-chain in the
 *            Provisional state and only become Confirmed after a
 *            challenge window. During the window any watchdog can open a
 *            dispute; Falcon verification itself stays off-chain (direct
 *            on-chain Falcon verification costs ~5e8 gas and exceeds the
 *            block gas limit), but it is now enforced as a *contestable*
 *            obligation backed by stakes, not an unverified relay claim.
 *
 *         4. Committee adjudication. Disputes are resolved by t-of-n
 *            ECDSA attestations from staked verifier nodes that re-run
 *            Falcon verification off-chain. Confirmed fraud revokes the
 *            record and slashes the relay; a spurious dispute slashes the
 *            challenger; verifiers on the losing side of a resolved
 *            dispute are slashed as well. The adjudication layer is an
 *            explicit transition-era trust assumption: it disappears
 *            once EVM-level FN-DSA support allows the same dispute path
 *            to verify Falcon directly on-chain.
 *
 * @dev Research prototype. Bond and bounty amounts are deployment
 *      parameters; the reference Hardhat benchmark uses 1 / 0.5 / 0.1 /
 *      0.5 / 0.25 ETH for relay stake, verifier stake, challenger bond,
 *      relay slash, and verifier slash respectively.
 */
contract AccountableRelay {
    // ------------------------------------------------------------------
    // Errors
    // ------------------------------------------------------------------
    error NotStakedRelay();
    error InactiveDID();
    error BadSignatureLength();
    error ReplayDetected();
    error BadAvailabilityLength();
    error BatchLengthMismatch();
    error DuplicateAttestation();
    error NotVerifier();
    error BadAttestation();
    error NothingToFinalize();
    error ChallengeWindowOpen();
    error NoDisputeOpen();
    error DisputeNotResolved();
    error BadMerkleProof();
    error UnknownDispute();
    error StillStaked();
    error UnderReview();
    error InsufficientBond();

    // ------------------------------------------------------------------
    // Types and storage
    // ------------------------------------------------------------------
    enum RecordState {
        Provisional, // inside the challenge window
        Confirmed, // window closed without a successful dispute
        Disputed, // an active dispute exists
        Revoked // fraud proven; excluded from the audit trail
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
        RecordState state;
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

    // Accountability economics (deployment-configurable; the reference
    // Hardhat benchmark uses 1 / 0.5 / 0.1 / 0.5 / 0.25 ETH).
    uint256 public immutable relayStakeAmount;
    uint256 public immutable verifierStakeAmount;
    uint256 public immutable challengerBondAmount;
    uint256 public immutable relaySlashAmount;
    uint256 public immutable verifierSlashAmount;
    uint256 public constant UNSTAKE_DELAY = 3 days;

    uint256 public constant FALCON_512_SIG_SIZE_MAX = 752;

    mapping(address => uint256) public relayStake;
    mapping(address => uint256) public relayExitTime;
    mapping(address => bool) public relayUnderReview;
    mapping(address => uint256) public verifierStake;

    mapping(bytes32 => uint256) public didNonce; // per-DID sequence numbers
    mapping(bytes32 => bool) public usedCommitments; // replay defence (single mode)

    Record[] private records;
    Batch[] private batches;
    Dispute[] private disputes;
    mapping(uint256 => mapping(address => bool)) private hasAttested;

    // ------------------------------------------------------------------
    // Events (consensus-critical data availability for batch leaves)
    // ------------------------------------------------------------------
    event RelayStaked(address indexed relay, uint256 amount);
    event RelayUnstaked(address indexed relay, uint256 amount);
    event VerifierStaked(address indexed verifier, uint256 amount);
    event RecordSubmitted(
        uint256 indexed index,
        bytes32 indexed didHash,
        uint256 nonce,
        bytes32 dataHash,
        address indexed relay
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
        uint256 indexed batchIndex,
        uint256 indexed leafIndex,
        bytes32 indexed didHash,
        uint256 nonce,
        bytes32 dataHash,
        bytes32 sigHash
    );
    event BatchFinalized(uint256 indexed batchIndex);
    event DisputeOpened(uint256 indexed disputeId, uint8 targetType, uint256 targetIndex, address challenger);
    event DisputeResolved(uint256 indexed disputeId, bool fraudProven);

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
    // Stake management
    // ------------------------------------------------------------------
    function stakeRelay() external payable {
        if (msg.value == 0) revert NotStakedRelay();
        relayStake[msg.sender] += msg.value;
        emit RelayStaked(msg.sender, msg.value);
    }

    function announceUnstake() external {
        if (relayStake[msg.sender] < relayStakeAmount) revert NotStakedRelay();
        if (relayUnderReview[msg.sender]) revert UnderReview();
        relayExitTime[msg.sender] = block.timestamp + UNSTAKE_DELAY;
    }

    function unstakeRelay() external {
        uint256 amount = relayStake[msg.sender];
        if (amount == 0) revert NotStakedRelay();
        if (relayUnderReview[msg.sender]) revert UnderReview();
        if (relayExitTime[msg.sender] == 0 || block.timestamp < relayExitTime[msg.sender]) {
            revert StillStaked();
        }
        relayStake[msg.sender] = 0;
        relayExitTime[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "unstake transfer failed");
        emit RelayUnstaked(msg.sender, amount);
    }

    function stakeVerifier() external payable {
        if (msg.value == 0) revert NotVerifier();
        verifierStake[msg.sender] += msg.value;
        emit VerifierStaked(msg.sender, msg.value);
    }

    // ------------------------------------------------------------------
    // 1. Accountable single-record submission
    // ------------------------------------------------------------------
    function submitAccountable(
        bytes32 dataHash,
        bytes32 didHash,
        bytes calldata falconSignature
    ) external returns (uint256 index) {
        if (relayStake[msg.sender] < relayStakeAmount) revert NotStakedRelay();
        if (!didRegistry.isActive(didHash)) revert InactiveDID();
        if (falconSignature.length == 0 || falconSignature.length > FALCON_512_SIG_SIZE_MAX) {
            revert BadSignatureLength();
        }

        // Context binding: nonce assigned on-chain, commitment domain-separated.
        uint256 nonce = ++didNonce[didHash];
        bytes32 commitment =
            keccak256(abi.encode(block.chainid, address(this), didHash, nonce, dataHash, keccak256(falconSignature)));
        if (usedCommitments[commitment]) revert ReplayDetected();
        usedCommitments[commitment] = true;

        bytes memory pubKey = didRegistry.getPublicKey(didHash);

        index = records.length;
        records.push(
            Record({
                dataHash: dataHash,
                didHash: didHash,
                falconSignature: falconSignature,
                pubKeyHash: keccak256(pubKey),
                submittedAt: uint64(block.timestamp),
                relay: msg.sender, // attributable endorsement
                nonce: nonce,
                state: RecordState.Provisional // optimistic: not yet final
             })
        );

        emit RecordSubmitted(index, didHash, nonce, dataHash, msg.sender);
    }

    // ------------------------------------------------------------------
    // 2. Permissionless finalization after the challenge window
    // ------------------------------------------------------------------
    function finalizeRecord(uint256 index) external {
        Record storage r = records[index];
        if (r.state != RecordState.Provisional) revert NothingToFinalize();
        if (block.timestamp < r.submittedAt + challengePeriod) revert ChallengeWindowOpen();
        r.state = RecordState.Confirmed;
        emit RecordFinalized(index);
    }

    // ------------------------------------------------------------------
    // 3. Accountable batch submission with bound Merkle leaves
    //
    //    availabilityData carries the concatenated raw Falcon signatures
    //    (padded to FALCON_512_SIG_SIZE_MAX each); the transaction
    //    calldata itself is the publication layer for offline
    //    re-verification (upgradeable to EIP-4844 blobs, which would
    //    store only the versioned blob hash on-chain).
    //
    //    leaf_i = keccak256(BATCH_LEAF_DOMAIN, chainid, this,
    //                       batchIndex, did_i, nonce_i, dataHash_i, sigHash_i)
    //
    //    Nonces are assigned on-chain and the tree is constructed by the
    //    contract, so every leaf is bound to its DID, payload, signature
    //    and batch context before the root ever reaches storage.
    // ------------------------------------------------------------------
    function submitBatch(
        bytes32[] calldata didHashes,
        bytes32[] calldata dataHashes,
        bytes calldata availabilityData
    ) external returns (uint256 batchIndex, bytes32 root) {
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
                state: RecordState.Provisional
            })
        );

        emit BatchSubmitted(batchIndex, root, k, keccak256(availabilityData), msg.sender);
    }

    function finalizeBatch(uint256 batchIndex) external {
        Batch storage b = batches[batchIndex];
        if (b.state != RecordState.Provisional) revert NothingToFinalize();
        if (block.timestamp < b.submittedAt + challengePeriod) revert ChallengeWindowOpen();
        b.state = RecordState.Confirmed;
        emit BatchFinalized(batchIndex);
    }

    // ------------------------------------------------------------------
    // 4. Disputes
    // ------------------------------------------------------------------
    function openDispute(uint256 recordIndex) external payable returns (uint256 disputeId) {
        if (msg.value < challengerBondAmount) revert InsufficientBond();
        Record storage r = records[recordIndex];
        if (r.state != RecordState.Provisional) revert NothingToFinalize();
        r.state = RecordState.Disputed;
        relayUnderReview[r.relay] = true;
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

        bytes32 leaf = _leafHash(batchIndex, didHash, nonce, dataHash, sigHash);
        if (!_verifyProof(leaf, merkleProof, leafIndex, b.merkleRoot)) revert BadMerkleProof();

        b.state = RecordState.Disputed;
        relayUnderReview[b.relay] = true;
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
     * @notice Submit a committee attestation for an open dispute.
     *         The signature must come from a staked verifier and authorize
     *         keccak256(ATTEST_DOMAIN, disputeId, verdictIsFraud, target binding).
     */
    function submitAttestation(uint256 disputeId, bool verdictIsFraud, bytes calldata signature) external {
        Dispute storage d = disputes[disputeId];
        if (d.deadline == 0) revert UnknownDispute();
        if (d.resolved || block.timestamp > d.deadline) revert NoDisputeOpen();

        bytes32 digest = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", _attestInner(disputeId, verdictIsFraud))
        );
        address signer = _recover(digest, signature);
        if (verifierStake[signer] < verifierStakeAmount) revert NotVerifier();
        if (hasAttested[disputeId][signer]) revert DuplicateAttestation();
        hasAttested[disputeId][signer] = true;

        if (verdictIsFraud) {
            d.fraudAttesters.push(signer);
        } else {
            d.validAttesters.push(signer);
        }

        if (d.fraudAttesters.length >= quorum) {
            _resolve(disputeId, true);
        } else if (d.validAttesters.length >= quorum) {
            _resolve(disputeId, false);
        }
    }

    /**
     * @notice Fail-closed expiry: a dispute that reaches its deadline
     *         without a quorum revokes the target and refunds bonds.
     */
    function expireDispute(uint256 disputeId) external {
        Dispute storage d = disputes[disputeId];
        if (d.deadline == 0) revert UnknownDispute();
        if (d.resolved) revert DisputeNotResolved();
        if (block.timestamp <= d.deadline) revert ChallengeWindowOpen();
        _revokeTarget(d);
        _refundChallenger(d);
        d.resolved = true;
        emit DisputeResolved(disputeId, true);
    }

    // ------------------------------------------------------------------
    // Resolution and slashing
    // ------------------------------------------------------------------
    function _resolve(uint256 disputeId, bool fraudProven) internal {
        Dispute storage d = disputes[disputeId];
        d.resolved = true;

        if (fraudProven) {
            // Slash the RELAY pool (fraudulent endorsement), bounty the
            // challenger, then slash wrong-side verifiers from their pool.
            address payable challenger = payable(d.challenger);
            _slashFromPool(
                d.targetType == 0 ? records[d.targetIndex].relay : batches[d.targetIndex].relay,
                relaySlashAmount,
                challenger,
                false
            );
            _refundChallenger(d);
            address[] storage wrongSide = d.validAttesters;
            for (uint256 i = 0; i < wrongSide.length; i++) {
                _slashFromPool(wrongSide[i], verifierSlashAmount, challenger, true);
            }
            _revokeTarget(d);
        } else {
            // Spurious dispute: the challenger bond compensates the relay.
            address payable relay = payable(d.targetType == 0 ? records[d.targetIndex].relay : batches[d.targetIndex].relay);
            (bool ok, ) = relay.call{value: d.bond}("");
            require(ok, "bond transfer failed");
            address[] storage wrongSide = d.fraudAttesters;
            for (uint256 i = 0; i < wrongSide.length; i++) {
                _slashFromPool(wrongSide[i], verifierSlashAmount, relay, true);
            }
            if (d.targetType == 0) {
                records[d.targetIndex].state = RecordState.Confirmed;
            } else {
                batches[d.targetIndex].state = RecordState.Confirmed;
            }
        }
        _clearReviewFlag(d);
        emit DisputeResolved(disputeId, fraudProven);
    }

    function _revokeTarget(Dispute storage d) internal {
        if (d.targetType == 0) {
            records[d.targetIndex].state = RecordState.Revoked;
        } else {
            batches[d.targetIndex].state = RecordState.Revoked;
        }
    }

    function _refundChallenger(Dispute storage d) internal {
        address payable challenger = payable(d.challenger);
        (bool ok, ) = challenger.call{value: d.bond}("");
        require(ok, "refund failed");
    }

    /**
     * @dev Slash `amount` from the specified stake pool of `from` (relay
     *      pool when `fromVerifierPool` is false, verifier pool otherwise)
     *      and pay it out to `to`. If the primary pool is short, the
     *      remainder is taken from the other pool so that value is never
     *      left ambiguous.
     */
    function _slashFromPool(address from, uint256 amount, address payable to, bool fromVerifierPool) internal {
        uint256 payout;
        if (fromVerifierPool) {
            uint256 vStake = verifierStake[from];
            uint256 take = vStake < amount ? vStake : amount;
            verifierStake[from] = vStake - take;
            amount -= take;
            payout += take;
            if (amount > 0) {
                uint256 rStake = relayStake[from];
                take = rStake < amount ? rStake : amount;
                relayStake[from] = rStake - take;
                payout += take;
            }
        } else {
            uint256 rStake = relayStake[from];
            uint256 take = rStake < amount ? rStake : amount;
            relayStake[from] = rStake - take;
            amount -= take;
            payout += take;
            if (amount > 0) {
                uint256 vStake = verifierStake[from];
                take = vStake < amount ? vStake : amount;
                verifierStake[from] = vStake - take;
                payout += take;
            }
        }
        if (payout > 0) {
            (bool ok, ) = to.call{value: payout}("");
            require(ok, "slash payout failed");
        }
    }

    function _clearReviewFlag(Dispute storage d) internal {
        address relay = d.targetType == 0 ? records[d.targetIndex].relay : batches[d.targetIndex].relay;
        relayUnderReview[relay] = false;
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
        return (
            r.dataHash, r.didHash, r.falconSignature, r.pubKeyHash, r.submittedAt, r.relay, r.nonce, r.state
        );
    }

    function getBatch(uint256 batchIndex)
        external
        view
        returns (bytes32 merkleRoot, uint256 leafCount, bytes32 availabilityCommitment, address relay, RecordState state)
    {
        Batch storage b = batches[batchIndex];
        return (b.merkleRoot, b.leafCount, b.availabilityCommitment, b.relay, b.state);
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

    function _attestInner(uint256 disputeId, bool verdictIsFraud) internal view returns (bytes32) {
        Dispute storage d = disputes[disputeId];
        return keccak256(
            abi.encode("ATTEST_DOMAIN_V1", disputeId, verdictIsFraud, d.targetType, d.targetIndex, d.leafIndex)
        );
    }

    /**
     * @notice The domain-separated digest that a committee verifier signs
     *         with a standard personal_sign (EIP-191) operation. The
     *         contract re-applies the EIP-191 prefix on-chain when
     *         recovering the signer.
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
