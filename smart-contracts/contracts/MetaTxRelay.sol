// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "./DIDRegistry.sol";

/**
 * @title MetaTxRelay
 * @notice Relay-assisted meta-transaction contract for post-quantum
 *         IoT blockchain interactions.
 *
 * Falcon-512 signature verification is performed OFF-CHAIN by the relay
 * node. This contract stores the transaction data, Falcon signature, and
 * DID reference on-chain for auditability and offline independent
 * verification. The gas cost of this approach is orders of magnitude
 * lower than attempting full on-chain Falcon verification (~5e8 gas),
 * which exceeds the Ethereum block gas limit (~1.2e7).
 *
 * @dev Trust model: This research prototype assumes a trusted relay
 *      operator. Multi-relay consensus is documented as future work.
 */
contract MetaTxRelay {
    /// @notice Maximum size of a Falcon-512 signature in bytes (PQCLEAN verified).
    uint256 public constant FALCON_512_SIG_SIZE_MAX = 752;

    DIDRegistry public didRegistry;

    struct VerifiedTransaction {
        bytes32 dataHash;
        bytes32 didHash;
        bytes falconSignature;
        bytes32 pubKeyHash;
        uint256 timestamp;
        bool verified;
    }

    VerifiedTransaction[] public transactions;
    uint256 public transactionCount;

    /// @notice Tracks commitment hashes to prevent replay attacks.
    mapping(bytes32 => bool) public usedCommitments;

    event TransactionSubmitted(
        uint256 indexed txIndex,
        bytes32 dataHash,
        bytes32 indexed didHash,
        bool verified
    );

    event ReplayAttempt(bytes32 indexed commitmentHash, address caller);

    constructor(address _didRegistry) {
        didRegistry = DIDRegistry(_didRegistry);
    }

    /**
     * @notice Submit a relay-assisted transaction.
     *         The relay node has already performed off-chain Falcon
     *         verification. This function stores the result on-chain.
     *
     * @param dataHash           Hash of the original IoT data payload.
     * @param didHash            Hash of the DID that signed the data.
     * @param falconSignature    The Falcon-512 signature (stored for offline audit).
     * @param verificationResult Whether the relay's off-chain Falcon verification passed.
     */
    function submitTransaction(
        bytes32 dataHash,
        bytes32 didHash,
        bytes calldata falconSignature,
        bool verificationResult
    ) external {
        require(falconSignature.length > 0 && falconSignature.length <= FALCON_512_SIG_SIZE_MAX, "Invalid signature length");

        // Verify the DID is registered and active
        require(didRegistry.isActive(didHash), "DID not active");

        // Replay protection: each unique (dataHash, didHash, signature) can only be submitted once
        bytes32 commitment = keccak256(abi.encodePacked(dataHash, didHash, falconSignature));
        require(!usedCommitments[commitment], "Replay: already submitted");
        usedCommitments[commitment] = true;

        // Snapshot public key hash at submission time for offline verification integrity
        bytes memory pubKey = didRegistry.getPublicKey(didHash);
        bytes32 pubKeyHash = keccak256(pubKey);

        uint256 txIndex = transactions.length;

        transactions.push(VerifiedTransaction({
            dataHash: dataHash,
            didHash: didHash,
            falconSignature: falconSignature,
            pubKeyHash: pubKeyHash,
            timestamp: block.timestamp,
            verified: verificationResult
        }));

        transactionCount++;

        emit TransactionSubmitted(txIndex, dataHash, didHash, verificationResult);
    }

    /**
     * @notice Retrieve a stored transaction for offline verification.
     *         Anyone can independently verify the Falcon-512 signature
     *         against the stored public key (from DID registry) without
     *         trusting the relay node.
     *
     * @param index Transaction index.
     * @return dataHash Hash of the original IoT data payload.
     * @return didHash Hash of the DID that signed the data.
     * @return falconSignature The Falcon-512 signature bytes.
     * @return pubKeyHash keccak256 hash of the public key at submission time.
     */
    function getTransactionForVerification(
        uint256 index
    ) external view returns (
        bytes32 dataHash,
        bytes32 didHash,
        bytes memory falconSignature,
        bytes32 pubKeyHash
    ) {
        require(index < transactions.length, "Index out of bounds");
        VerifiedTransaction storage txn = transactions[index];
        return (
            txn.dataHash,
            txn.didHash,
            txn.falconSignature,
            txn.pubKeyHash
        );
    }
}
