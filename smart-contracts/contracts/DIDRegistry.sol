// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/**
 * @title DIDRegistry
 * @notice On-chain registry for Decentralized Identifiers (DIDs)
 *         linked to Falcon-512 public keys.
 *
 * Each DID entry stores the owner address, the Falcon-512 public key
 * (897 bytes), a timestamp, and an active flag. This contract is used
 * by the MetaTxRelay contract to verify DID validity before accepting
 * relay-assisted transactions.
 *
 * @dev Trust model: This research prototype assumes a trusted relay
 *      operator. Multi-relay consensus and key rotation are documented
 *      as future work for production deployment.
 */
contract DIDRegistry {
    /// @notice Exact size of a Falcon-512 public key in bytes.
    uint256 public constant FALCON_512_PK_SIZE = 897;

    struct DIDDocument {
        address owner;
        bytes publicKey;
        uint256 registeredAt;
        bool active;
    }

    mapping(bytes32 => DIDDocument) public dids;

    event DIDRegistered(bytes32 indexed didHash, address indexed owner, uint256 timestamp);
    event DIDDeactivated(bytes32 indexed didHash, uint256 timestamp);

    /**
     * @notice Register a new DID with a Falcon-512 public key.
     * @param didHash          The keccak256 hash of the DID string.
     * @param falconPublicKey  The 897-byte Falcon-512 public key.
     */
    function registerDID(
        bytes32 didHash,
        bytes calldata falconPublicKey
    ) external {
        require(dids[didHash].registeredAt == 0, "DID already exists");
        require(falconPublicKey.length == FALCON_512_PK_SIZE, "Invalid public key length");

        dids[didHash] = DIDDocument({
            owner: msg.sender,
            publicKey: falconPublicKey,
            registeredAt: block.timestamp,
            active: true
        });

        emit DIDRegistered(didHash, msg.sender, block.timestamp);
    }

    /**
     * @notice Deactivate a DID. Only the owner can deactivate.
     * @param didHash The DID hash to deactivate.
     */
    function deactivateDID(bytes32 didHash) external {
        require(dids[didHash].owner == msg.sender, "Not owner");
        require(dids[didHash].active, "DID already deactivated");

        dids[didHash].active = false;

        emit DIDDeactivated(didHash, block.timestamp);
    }

    /**
     * @notice Retrieve the public key for a DID.
     *         Reverts if the DID does not exist or is deactivated.
     * @param didHash The DID hash.
     * @return The Falcon-512 public key bytes.
     */
    function getPublicKey(bytes32 didHash) external view returns (bytes memory) {
        require(dids[didHash].registeredAt != 0, "DID does not exist");
        require(dids[didHash].active, "DID is deactivated");
        return dids[didHash].publicKey;
    }

    /**
     * @notice Check whether a DID is registered and active.
     * @param didHash The DID hash.
     * @return True if the DID exists and is active.
     */
    function isActive(bytes32 didHash) external view returns (bool) {
        return dids[didHash].registeredAt != 0 && dids[didHash].active;
    }
}
