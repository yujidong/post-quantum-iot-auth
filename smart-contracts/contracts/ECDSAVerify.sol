// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/**
 * @title ECDSAVerify
 * @notice ECDSA signature verification contract for fair gas cost comparison.
 *
 * Provides two submission modes:
 *   1. submitAndVerify() — ecrecover + store dataHash + signer address (~35K gas)
 *   2. submitVerifyAndStore() — same + store full 64-byte ECDSA signature (~50K gas)
 *
 * The second mode is the fair comparison baseline for the relay meta-transaction,
 * since both paths store a full signature on-chain (ECDSA: 64 bytes, Falcon: ≤752 bytes).
 *
 * Also supports registered signer verification: transactions can be restricted
 * to pre-registered signers for enhanced security.
 */
contract ECDSAVerify {
    bytes32 public latestDataHash;
    address public latestSigner;

    /// @notice Stores a full ECDSA signature (r, s) on-chain for audit.
    bytes32 public latestSigR;
    bytes32 public latestSigS;

    /// @notice Registered signers allowed to submit verified transactions.
    mapping(address => bool) public registeredSigners;

    /// @notice Whether signer verification is enabled.
    bool public signerVerificationEnabled;

    event DataVerified(bytes32 indexed dataHash, address indexed signer);
    event DataVerifiedWithSig(bytes32 indexed dataHash, address indexed signer);
    event SignerRegistered(address indexed signer);
    event SignerVerificationEnabled(bool enabled);

    constructor() {
        signerVerificationEnabled = false;
    }

    /**
     * @notice Enable or disable signer verification.
     * @param enabled True to require registered signers.
     */
    function setSignerVerification(bool enabled) external {
        signerVerificationEnabled = enabled;
        emit SignerVerificationEnabled(enabled);
    }

    /**
     * @notice Register a signer address for verified submission.
     * @param signer The address allowed to submit transactions.
     */
    function registerSigner(address signer) external {
        registeredSigners[signer] = true;
        emit SignerRegistered(signer);
    }

    /**
     * @notice Submit data with ECDSA signature verification.
     * @param dataHash  keccak256 hash of the data payload.
     * @param v         Recovery byte of the signature.
     * @param r         First 32 bytes of the signature.
     * @param s         Second 32 bytes of the signature.
     */
    function submitAndVerify(
        bytes32 dataHash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        address signer = ecrecover(dataHash, v, r, s);
        require(signer != address(0), "Invalid signature");
        if (signerVerificationEnabled) {
            require(registeredSigners[signer], "Signer not registered");
        }
        latestDataHash = dataHash;
        latestSigner = signer;
        emit DataVerified(dataHash, signer);
    }

    /**
     * @notice Submit data with ECDSA verification AND store the full signature.
     *
     * This is the fair comparison baseline: stores 64 bytes of signature data
     * on-chain (r + s), mirroring how MetaTxRelay stores the Falcon signature.
     * Gas cost is ~50-65K due to the additional SSTORE operations.
     *
     * @param dataHash  keccak256 hash of the data payload.
     * @param v         Recovery byte of the signature.
     * @param r         First 32 bytes of the signature.
     * @param s         Second 32 bytes of the signature.
     */
    function submitVerifyAndStore(
        bytes32 dataHash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        address signer = ecrecover(dataHash, v, r, s);
        require(signer != address(0), "Invalid signature");
        if (signerVerificationEnabled) {
            require(registeredSigners[signer], "Signer not registered");
        }
        latestDataHash = dataHash;
        latestSigner = signer;
        latestSigR = r;
        latestSigS = s;
        emit DataVerifiedWithSig(dataHash, signer);
    }
}
