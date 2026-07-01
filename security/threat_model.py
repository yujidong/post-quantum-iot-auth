"""
Formal threat model for the Post-Quantum IoT Blockchain Architecture.

Defines threat actors, security assumptions, guarantees, and known
limitations of the architecture. This supplements the implementation
correctness tests in attack_simulation.py.
"""

THREAT_MODEL = {
    "architecture": "Post-Quantum Secure Blockchain Edge Architecture for IoT",
    "signature_scheme": "Falcon-512 (NIST FIPS 205, Level 1)",
    "blockchain": "EVM-compatible (tested on Hardhat, Solidity 0.8.24)",

    "threat_actors": [
        {
            "name": "Classical Adversary",
            "capabilities": "Classical computer, can intercept network traffic, "
                          "observe public keys and blockchain data",
            "mitigated_by": "Falcon-512 EU-CMA security (2^-128 forgery probability). "
                          "Off-chain verification at gateway prevents invalid data from reaching blockchain.",
        },
        {
            "name": "Quantum Adversary",
            "capabilities": "Quantum computer with Shor's algorithm and Grover's algorithm",
            "mitigated_by": "Falcon-512 is based on NTRU lattice problems (quantum-resistant). "
                          "Shor's algorithm breaks ECDSA in polynomial time O(n^3) but "
                          "does NOT break Falcon's lattice-based security. "
                          "Grover's algorithm only provides quadratic speedup against Falcon "
                          "(reduces security from 2^128 to 2^64, still infeasible).",
        },
        {
            "name": "Malicious Relay",
            "capabilities": "Controls relay node, can read/modify relay traffic, "
                          "refuse to forward transactions",
            "mitigated_by": "Relay is trusted for AVAILABILITY only, not for INTEGRITY. "
                          "Gateway performs Falcon verification BEFORE relay receives data. "
                          "Relay cannot forge signatures (no private key). "
                          "Relay cannot modify payloads (signature bound to payload). "
                          "Relay can censor/reorder/refuse (availability attack only).",
            "limitations": "A compromised relay can mount a denial-of-service by refusing "
                         "to forward transactions. Multi-relay consensus (future work) "
                         "would mitigate this.",
        },
        {
            "name": "Compromised IoT Device",
            "capabilities": "Attacker gains control of IoT device, extracts private key",
            "mitigated_by": "DID deactivation mechanism removes compromised identity. "
                          "Key rotation generates new independent key pair. "
                          "Old signatures are invalidated after deactivation.",
            "limitations": "Detection of compromise depends on out-of-band monitoring. "
                         "There is a window between compromise and deactivation.",
        },
        {
            "name": "Replay Attacker",
            "capabilities": "Captures valid transactions and resubmits them",
            "mitigated_by": "On-chain commitment tracking in MetaTxRelay.sol: "
                          "keccak256(dataHash || didHash || signature) is stored and "
                          "checked for each submission. Duplicate commitments are rejected.",
        },
    ],

    "security_guarantees": [
        {
            "property": "Existential Unforgeability under Chosen Message Attack (EU-CMA)",
            "basis": "Falcon-512 is provably EU-CMA secure under the NTRU assumption "
                    "(NIST FIPS 205, IR 8413). Security level: 128 bits (AES-128 equivalent).",
            "scope": "No adversary (classical or quantum) can forge a valid signature "
                    "without the private key, except with negligible probability 2^(-128).",
        },
        {
            "property": "Data Integrity",
            "basis": "Falcon signature binds the payload hash to the device's public key. "
                    "Gateway verification ensures only signed data reaches the blockchain.",
            "scope": "Data cannot be modified in transit without invalidating the signature.",
        },
        {
            "property": "Replay Resistance",
            "basis": "On-chain commitment tracking (MetaTxRelay.sol, line 77-79). "
                    "Each (dataHash, didHash, signature) tuple can only be submitted once.",
            "scope": "Exact replay of any previously submitted transaction is rejected.",
        },
        {
            "property": "Identity Revocation",
            "basis": "DIDRegistry.sol deactivateDID() function marks identity as inactive. "
                    "MetaTxRelay.sol checks isActive() before accepting transactions.",
            "scope": "Compromised identities can be disabled, preventing future transactions.",
        },
        {
            "property": "Key Independence",
            "basis": "Each Falcon key generation produces statistically independent keys. "
                    "Compromise of one key does not affect others.",
            "scope": "Key rotation produces a fully independent key pair.",
        },
    ],

    "known_limitations": [
        {
            "limitation": "Relay Availability Trust",
            "description": "The relay node is trusted for availability. A compromised relay "
                         "can censor transactions but cannot forge or modify them.",
            "mitigation": "Future work: multi-relay consensus or BFT relay pool.",
        },
        {
            "limitation": "No Confidentiality",
            "description": "The architecture does not provide data confidentiality. "
                         "IoT sensor data is stored on-chain in plaintext via data hashes. "
                         "Full payloads are stored off-chain at the gateway.",
            "mitigation": "Add encryption layer (e.g., ECIES-KEM) before gateway submission.",
        },
        {
            "limitation": "No Forward Secrecy for Signatures",
            "description": "If a device's private key is compromised, all previously "
                         "signed messages remain valid (Falcon signatures do not degrade).",
            "mitigation": "This is inherent to all signature schemes. Mitigated by "
                         "prompt key rotation upon compromise detection.",
        },
        {
            "limitation": "Gas Cost of Relay Meta-Transactions",
            "description": "Meta-transactions cost ~820K gas per transaction (storing "
                         "752-byte Falcon signature on-chain). This is ~16x more expensive "
                         "than ECDSA direct submission (~50K gas).",
            "mitigation": "Acceptable trade-off for quantum security. Future: signature "
                         "compression or ZK proofs to reduce on-chain storage.",
        },
        {
            "limitation": "Single Gateway Verification",
            "description": "Current architecture uses a single gateway for off-chain "
                         "verification. If the gateway is compromised, it could forward "
                         "unverified data to the relay.",
            "mitigation": "Gateway is assumed trusted. Multi-gateway redundancy is future work.",
        },
    ],

    "security_comparison": {
        "this_work": {
            "pq_scheme": "Falcon-512",
            "nist_level": 1,
            "quantum_safe": True,
            "did_integration": True,
            "meta_transactions": True,
            "replay_protection": "On-chain commitment tracking",
            "key_recovery": "DID deactivation + key rotation",
            "gas_per_tx": "~820K (Hardhat measured)",
        },
        "ecdsa_baseline": {
            "pq_scheme": "ECDSA (secp256k1)",
            "nist_level": "N/A (classical only)",
            "quantum_safe": False,
            "vulnerability": "Shor's algorithm: O(n^3) on quantum computer. "
                           "Public key → private key recovery in polynomial time.",
            "did_integration": False,
            "meta_transactions": False,
            "gas_per_tx": "~50K",
        },
    },
}


def get_threat_model() -> dict:
    """Return the complete threat model as a dictionary."""
    return THREAT_MODEL


def get_threat_model_summary() -> str:
    """Return a human-readable summary of the threat model."""
    lines = ["=" * 60]
    lines.append("THREAT MODEL SUMMARY")
    lines.append("=" * 60)
    lines.append(f"Architecture: {THREAT_MODEL['architecture']}")
    lines.append(f"Signature: {THREAT_MODEL['signature_scheme']}")
    lines.append("")

    lines.append("THREAT ACTORS:")
    for actor in THREAT_MODEL["threat_actors"]:
        lines.append(f"  - {actor['name']}: {actor['mitigated_by']}")
    lines.append("")

    lines.append("SECURITY GUARANTEES:")
    for g in THREAT_MODEL["security_guarantees"]:
        lines.append(f"  - {g['property']}: {g['basis']}")
    lines.append("")

    lines.append("KNOWN LIMITATIONS:")
    for l in THREAT_MODEL["known_limitations"]:
        lines.append(f"  - {l['limitation']}: {l['description']}")
    lines.append("")

    lines.append("QUANTUM SAFETY COMPARISON:")
    comp = THREAT_MODEL["security_comparison"]
    lines.append(f"  This work ({comp['this_work']['pq_scheme']}): quantum-safe = {comp['this_work']['quantum_safe']}")
    lines.append(f"  Baseline ({comp['ecdsa_baseline']['pq_scheme']}): quantum-safe = {comp['ecdsa_baseline']['quantum_safe']}")
    lines.append(f"    Vulnerability: {comp['ecdsa_baseline']['vulnerability']}")
    lines.append("=" * 60)

    return "\n".join(lines)
