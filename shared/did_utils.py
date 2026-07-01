"""
Decentralized Identifier (DID) utilities for the post-quantum
blockchain IoT experiment framework.

DID format: did:falconiot:<hex-identifier>
Supports serialization and bytes32 conversion for Solidity compatibility.
"""

import hashlib
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

DID_METHOD = "falconiot"
DID_PREFIX = f"did:{DID_METHOD}:"
DID_IDENTIFIER_LENGTH = 32  # hex chars after prefix


class DIDNotFoundError(Exception):
    """Raised when a bytes32 DID hash is not found in the registry."""

    pass


@dataclass
class DIDDocument:
    """Represents a DID document for an IoT device or gateway."""

    did: str
    public_key: bytes
    created_at: float = field(default_factory=time.time)
    active: bool = True

    def to_dict(self) -> dict:
        """Serialize DID document to a dictionary."""
        return {
            "did": self.did,
            "public_key": self.public_key.hex(),
            "created_at": self.created_at,
            "active": self.active,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "DIDDocument":
        """Deserialize DID document from a dictionary."""
        return cls(
            did=data["did"],
            public_key=bytes.fromhex(data["public_key"]),
            created_at=data["created_at"],
            active=data["active"],
        )


def generate_did(
    namespace: Optional[str] = None,
    seed: Optional[bytes] = None,
) -> str:
    """Generate a unique DID identifier.

    Args:
        namespace: Optional namespace to include in the DID.
        seed: Optional seed bytes for deterministic generation.

    Returns:
        DID string in format: did:falconiot:<hex>
    """
    if seed is not None:
        raw = hashlib.sha256(seed).hexdigest()[:DID_IDENTIFIER_LENGTH]
    else:
        raw = os.urandom(DID_IDENTIFIER_LENGTH // 2 + 1).hex()[:DID_IDENTIFIER_LENGTH]

    if namespace is not None:
        return f"{DID_PREFIX}{namespace}:{raw}"

    return f"{DID_PREFIX}{raw}"


def create_did_document(did: str, public_key: bytes) -> DIDDocument:
    """Create a DID document linking a DID to a public key.

    Args:
        did: The DID identifier string.
        public_key: The Falcon-512 public key bytes.

    Returns:
        A DIDDocument instance.
    """
    return DIDDocument(
        did=did,
        public_key=public_key,
        created_at=time.time(),
        active=True,
    )


def verify_did_document(doc: DIDDocument) -> bool:
    """Verify that a DID document is valid.

    A valid document must:
    - Have a non-empty DID string starting with 'did:'
    - Have a non-empty public key
    - Be active

    Args:
        doc: The DIDDocument to verify.

    Returns:
        True if the document is valid, False otherwise.
    """
    if not doc.did or not doc.did.startswith("did:"):
        return False
    if not doc.public_key:
        return False
    if not doc.active:
        return False
    return True


def _hash_did(did: str) -> bytes:
    """Hash a DID string to 32 bytes using SHA-256."""
    return hashlib.sha256(did.encode("utf-8")).digest()


# ---------------------------------------------------------------------------
# DID Registry: manages bytes32 <-> DID reverse lookups.
# Thread-safe via a lock. Call clear_registry() between test runs.
# ---------------------------------------------------------------------------

_did_registry: dict[bytes, str] = {}
_registry_lock = threading.Lock()


def did_to_bytes32(did: str) -> bytes:
    """Convert a DID string to 32 bytes and register for reverse lookup.

    Args:
        did: The DID string.

    Returns:
        32-byte SHA-256 hash representation.
    """
    b32 = _hash_did(did)
    with _registry_lock:
        _did_registry[b32] = did
    return b32


def bytes32_to_did(b32: bytes) -> str:
    """Look up the original DID string from its bytes32 hash.

    Args:
        b32: The 32-byte DID hash (previously returned by did_to_bytes32).

    Returns:
        The original DID string.

    Raises:
        DIDNotFoundError: If the bytes32 was never registered.
    """
    with _registry_lock:
        if b32 not in _did_registry:
            raise DIDNotFoundError(
                f"DID not found for bytes32: {b32.hex()}. "
                "Call did_to_bytes32() first to register."
            )
        return _did_registry[b32]


def register_did(did: str) -> bytes:
    """Register a DID and return its bytes32 representation.

    Equivalent to calling did_to_bytes32(). Provided for explicit
    clarity when registration is the primary intent.

    Args:
        did: The DID string to register.

    Returns:
        The 32-byte hash representation.
    """
    return did_to_bytes32(did)


def unregister_did(did: str) -> None:
    """Remove a DID from the registry.

    Args:
        did: The DID string to unregister.

    Raises:
        DIDNotFoundError: If the DID was not registered.
    """
    b32 = _hash_did(did)
    with _registry_lock:
        if b32 not in _did_registry:
            raise DIDNotFoundError(f"DID not registered: {did}")
        del _did_registry[b32]


def clear_registry() -> None:
    """Clear all entries from the DID registry.

    Call this between test runs to ensure test isolation.
    """
    with _registry_lock:
        _did_registry.clear()
