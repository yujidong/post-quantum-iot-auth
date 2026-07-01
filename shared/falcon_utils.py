"""
Falcon-512 cryptographic utilities for the post-quantum blockchain IoT
experiment framework.

Backend priority:
  1. liboqs (via liboqs-python) — the official Open Quantum Safe library.
     Built from source inside the Docker container on Linux.
  2. pqcrypto — pre-built wheels with PQCLEAN implementations.
     Used as fallback on platforms where liboqs is not available.
  3. simulation — Ed25519-based fallback with padded sizes.
     For development only, does NOT provide post-quantum security.

The Docker container (docker compose build) builds liboqs from source,
so the primary backend is always available in the containerized environment.
"""

import hashlib
import logging
import os
import warnings
from dataclasses import dataclass
from typing import Optional

from shared.config import (
    FALCON_512_PRIVATE_KEY_SIZE,
    FALCON_512_PUBLIC_KEY_SIZE,
    FALCON_512_SIGNATURE_SIZE_MAX,
)

_logger = logging.getLogger(__name__)

# ── Backend detection ──

_oqs_available = False
_oqs_module = None
_pqcrypto_available = False
_pqcrypto_falcon = None

# Try liboqs-python first (official OQS library, available in Docker container).
# On Windows, importing oqs triggers a FATAL auto-download that calls SystemExit.
# We must detect this case without importing the module.
import platform as _platform

if _platform.system() == "Linux":
    # Only attempt liboqs import on Linux (Docker container)
    try:
        import importlib
        _oqs_module = importlib.import_module("oqs")
        _sig = _oqs_module.Signature("Falcon-512")
        del _sig
        _oqs_available = True
    except Exception as exc:
        _logger.debug("liboqs import failed: %s", exc)
        _oqs_available = False
        _oqs_module = None
else:
    _logger.debug(
        "Skipping liboqs on %s — use Docker container for liboqs backend",
        _platform.system(),
    )

# Try pqcrypto as fallback (pre-built wheels, works on Windows/macOS)
if not _oqs_available:
    try:
        from pqcrypto.sign import falcon_512 as _falcon_module
        _pqcrypto_falcon = _falcon_module
        _pqcrypto_available = True
    except ImportError as exc:
        _logger.debug("pqcrypto import failed: %s", exc)
        _pqcrypto_available = False
        _pqcrypto_falcon = None

# Determine active backend
if _oqs_available:
    oqs = _oqs_module
    _BACKEND = "liboqs"
elif _pqcrypto_available:
    _BACKEND = "pqcrypto"
else:
    _BACKEND = "simulation"
    warnings.warn(
        "Neither liboqs nor pqcrypto available. Using simulation backend "
        "(Ed25519-based). For real PQC: run inside Docker container "
        "(docker compose run --rm experiments) or install pqcrypto: "
        "pip install pqcrypto",
        stacklevel=2,
    )


def get_backend() -> str:
    """Return the current crypto backend name."""
    return _BACKEND


@dataclass
class FalconKeyPair:
    """Container for a Falcon-512 key pair."""
    public_key: bytes
    private_key: bytes


# ---------------------------------------------------------------------------
# Simulation backend (Ed25519-based, preserves Falcon-512 sizes)
# ---------------------------------------------------------------------------


def _deterministic_pad(data: bytes, label: bytes, target_len: int) -> bytes:
    """Extend *data* to exactly *target_len* bytes using repeated SHA-256."""
    buf = data
    counter = 0
    while len(buf) < target_len:
        buf += hashlib.sha256(label + counter.to_bytes(4, "big")).digest()
        counter += 1
    return buf[:target_len]


def _simulation_keygen(seed: Optional[bytes] = None) -> FalconKeyPair:
    """Generate a simulated key pair with Falcon-512-sized keys."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    if seed is not None:
        derived = hashlib.sha256(b"falcon-sim-seed" + seed).digest()
        priv = Ed25519PrivateKey.from_private_bytes(derived)
    else:
        priv = Ed25519PrivateKey.generate()

    raw_priv = priv.private_bytes_raw()
    raw_pub = priv.public_key().public_bytes_raw()

    padded_pub = _deterministic_pad(
        raw_pub, b"pub_pad:" + raw_pub, FALCON_512_PUBLIC_KEY_SIZE
    )
    padded_priv = _deterministic_pad(
        raw_priv, b"priv_pad:" + raw_priv, FALCON_512_PRIVATE_KEY_SIZE
    )

    return FalconKeyPair(public_key=padded_pub, private_key=padded_priv)


def _simulation_sign(message: bytes, private_key: bytes) -> bytes:
    """Sign using Ed25519 and pad to Falcon-512 signature size."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    raw_priv = private_key[:32]
    priv = Ed25519PrivateKey.from_private_bytes(raw_priv)
    raw_sig = priv.sign(message)

    return _deterministic_pad(
        raw_sig, b"sig_pad:" + raw_sig, FALCON_512_SIGNATURE_SIZE_MAX
    )


def _simulation_verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """Verify a simulated signature."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PublicKey,
    )

    raw_sig = signature[:64]
    raw_pub = public_key[:32]

    try:
        pub = Ed25519PublicKey.from_public_bytes(raw_pub)
        pub.verify(raw_sig, message)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# liboqs backend (official Open Quantum Safe)
# ---------------------------------------------------------------------------


def _liboqs_keygen(seed: Optional[bytes] = None) -> FalconKeyPair:
    """Generate a real Falcon-512 key pair via liboqs."""
    with oqs.Signature("Falcon-512") as signer:
        if seed is not None:
            public_key = signer.generate_keypair(seed)
        else:
            public_key = signer.generate_keypair()
        private_key = signer.export_secret_key()
    return FalconKeyPair(public_key=public_key, private_key=private_key)


def _liboqs_sign(message: bytes, private_key: bytes) -> bytes:
    """Sign using real Falcon-512 via liboqs."""
    with oqs.Signature("Falcon-512", secret_key=private_key) as signer:
        return signer.sign(message)


def _liboqs_verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """Verify a real Falcon-512 signature via liboqs."""
    with oqs.Signature("Falcon-512") as verifier:
        return verifier.verify(message, signature, public_key)


# ---------------------------------------------------------------------------
# pqcrypto backend (PQCLEAN pre-built wheels, fallback)
# ---------------------------------------------------------------------------


def _pqcrypto_keygen(seed: Optional[bytes] = None) -> FalconKeyPair:
    """Generate a real Falcon-512 key pair via pqcrypto."""
    if seed is not None:
        _logger.warning("pqcrypto Falcon-512 does not support seeded keygen; seed ignored")
    pk, sk = _pqcrypto_falcon.generate_keypair()
    return FalconKeyPair(public_key=pk, private_key=sk)


def _pqcrypto_sign(message: bytes, private_key: bytes) -> bytes:
    """Sign using real Falcon-512 via pqcrypto.

    Note: Falcon-512 signatures are VARIABLE LENGTH (avg ~666B, max 752B).
    """
    return _pqcrypto_falcon.sign(private_key, message)


def _pqcrypto_verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """Verify a real Falcon-512 signature via pqcrypto."""
    try:
        return _pqcrypto_falcon.verify(public_key, message, signature)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Public API (dispatches to correct backend)
# ---------------------------------------------------------------------------


def falcon_keygen(seed: Optional[bytes] = None) -> FalconKeyPair:
    """Generate a Falcon-512 key pair.

    Args:
        seed: Optional seed for deterministic key generation.
              Only supported by liboqs and simulation backends.

    Returns:
        FalconKeyPair with public_key and private_key.
    """
    if _oqs_available:
        return _liboqs_keygen(seed)
    if _pqcrypto_available:
        return _pqcrypto_keygen(seed)
    return _simulation_keygen(seed)


def falcon_sign(message: bytes, private_key: bytes) -> bytes:
    """Sign a message.

    Args:
        message: Message bytes to sign.
        private_key: Falcon-512 private key.

    Returns:
        Signature bytes. Falcon-512 signatures are VARIABLE LENGTH
        (avg ~666B, max 752B).
    """
    if _oqs_available:
        return _liboqs_sign(message, private_key)
    if _pqcrypto_available:
        return _pqcrypto_sign(message, private_key)
    return _simulation_sign(message, private_key)


def falcon_verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """Verify a signature.

    Args:
        message: Original message bytes.
        signature: Signature to verify.
        public_key: Falcon-512 public key.

    Returns:
        True if valid, False otherwise.
    """
    if _oqs_available:
        return _liboqs_verify(message, signature, public_key)
    if _pqcrypto_available:
        return _pqcrypto_verify(message, signature, public_key)
    return _simulation_verify(message, signature, public_key)


def falcon_sign_message(message: bytes, keypair: FalconKeyPair) -> bytes:
    """Convenience: sign using a FalconKeyPair."""
    return falcon_sign(message, keypair.private_key)


def falcon_verify_message(
    message: bytes, signature: bytes, keypair: FalconKeyPair
) -> bool:
    """Convenience: verify using a FalconKeyPair."""
    return falcon_verify(message, signature, keypair.public_key)
