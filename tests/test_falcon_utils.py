"""
Tests for falcon_utils.py — TDD tests.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from shared.config import (
    FALCON_512_PRIVATE_KEY_SIZE,
    FALCON_512_PUBLIC_KEY_SIZE,
    FALCON_512_SIGNATURE_SIZE_MAX,
)
from shared.falcon_utils import (
    FalconKeyPair,
    falcon_keygen,
    falcon_sign,
    falcon_verify,
    get_backend,
    falcon_sign_message,
    falcon_verify_message,
    _pqcrypto_available,
    _oqs_available,
)


class TestBackend:
    """Test backend detection."""

    def test_backend_is_valid(self):
        assert get_backend() in ("liboqs", "pqcrypto", "simulation")

    def test_backend_is_pqcrypto_when_available(self):
        """The pqcrypto backend is used when liboqs is unavailable."""
        if _oqs_available:
            pytest.skip("liboqs is available, so pqcrypto is not the primary backend")
        if _pqcrypto_available:
            assert get_backend() == "pqcrypto"


class TestFalconKeyGen:
    """Test Falcon-512 key generation."""

    def test_keygen_returns_keypair(self):
        kp = falcon_keygen()
        assert isinstance(kp, FalconKeyPair)

    def test_public_key_correct_size(self):
        kp = falcon_keygen()
        assert len(kp.public_key) == FALCON_512_PUBLIC_KEY_SIZE

    def test_private_key_correct_size(self):
        kp = falcon_keygen()
        assert len(kp.private_key) == FALCON_512_PRIVATE_KEY_SIZE

    def test_keygen_deterministic_with_seed_simulation_only(self):
        """Seeded keygen is only supported by the simulation and liboqs backends."""
        if _oqs_available or _pqcrypto_available:
            pytest.skip("Seeded keygen test only applicable for simulation backend")
        seed = b"\x01" * 48
        kp1 = falcon_keygen(seed=seed)
        kp2 = falcon_keygen(seed=seed)
        assert kp1.public_key == kp2.public_key
        assert kp1.private_key == kp2.private_key

    def test_keygen_different_without_seed(self):
        kp1 = falcon_keygen()
        kp2 = falcon_keygen()
        assert kp1.public_key != kp2.public_key


class TestFalconSign:
    """Test Falcon-512 signing."""

    def test_sign_returns_bytes(self):
        kp = falcon_keygen()
        message = b"test message for signing"
        sig = falcon_sign(message, kp.private_key)
        assert isinstance(sig, bytes)

    def test_signature_size_reasonable(self):
        kp = falcon_keygen()
        message = b"test message for signing"
        sig = falcon_sign(message, kp.private_key)
        # pqcrypto: variable length ~640-752 bytes
        # simulation: padded to FALCON_512_SIGNATURE_SIZE_MAX
        assert 600 <= len(sig) <= FALCON_512_SIGNATURE_SIZE_MAX

    def test_sign_different_messages_different_signatures(self):
        kp = falcon_keygen()
        sig1 = falcon_sign(b"message one", kp.private_key)
        sig2 = falcon_sign(b"message two", kp.private_key)
        assert sig1 != sig2


class TestFalconVerify:
    """Test Falcon-512 verification."""

    def test_verify_valid_signature(self):
        kp = falcon_keygen()
        message = b"test message for verification"
        sig = falcon_sign(message, kp.private_key)
        assert falcon_verify(message, sig, kp.public_key) is True

    def test_verify_wrong_message(self):
        kp = falcon_keygen()
        sig = falcon_sign(b"original message", kp.private_key)
        assert falcon_verify(b"tampered message", sig, kp.public_key) is False

    def test_verify_wrong_key(self):
        kp1 = falcon_keygen()
        kp2 = falcon_keygen()
        sig = falcon_sign(b"test message", kp1.private_key)
        assert falcon_verify(b"test message", sig, kp2.public_key) is False

    def test_verify_tampered_signature(self):
        kp = falcon_keygen()
        message = b"test message"
        sig = falcon_sign(message, kp.private_key)
        tampered_sig = bytearray(sig)
        tampered_sig[10] ^= 0xFF
        assert falcon_verify(message, bytes(tampered_sig), kp.public_key) is False


class TestFalconConvenience:
    """Test convenience functions for full sign-verify workflow."""

    def test_sign_verify_message_roundtrip(self):
        kp = falcon_keygen()
        message = b"full workflow test"
        sig = falcon_sign_message(message, kp)
        assert falcon_verify_message(message, sig, kp) is True

    def test_sign_verify_empty_message(self):
        kp = falcon_keygen()
        message = b""
        sig = falcon_sign_message(message, kp)
        assert falcon_verify_message(message, sig, kp) is True

    def test_sign_verify_large_message(self):
        kp = falcon_keygen()
        message = b"x" * 10000
        sig = falcon_sign_message(message, kp)
        assert falcon_verify_message(message, sig, kp) is True
