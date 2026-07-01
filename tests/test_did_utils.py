"""
Tests for did_utils.py — TDD tests.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from shared.did_utils import (
    DIDDocument,
    DIDNotFoundError,
    bytes32_to_did,
    clear_registry,
    create_did_document,
    did_to_bytes32,
    generate_did,
    register_did,
    unregister_did,
    verify_did_document,
)


class TestDIDGeneration:
    """Test DID identifier generation."""

    def test_generate_did_returns_string(self):
        did = generate_did()
        assert isinstance(did, str)

    def test_generate_did_format(self):
        did = generate_did()
        assert did.startswith("did:falconiot:")

    def test_generate_did_unique(self):
        did1 = generate_did()
        did2 = generate_did()
        assert did1 != did2

    def test_generate_did_with_namespace(self):
        did = generate_did(namespace="sensor01")
        assert did.startswith("did:falconiot:sensor01:")

    def test_generate_did_deterministic_with_seed(self):
        did1 = generate_did(seed=b"test-seed-12345")
        did2 = generate_did(seed=b"test-seed-12345")
        assert did1 == did2


class TestDIDDocument:
    """Test DID document creation and verification."""

    def test_create_did_document(self):
        did = generate_did()
        from shared.falcon_utils import falcon_keygen

        kp = falcon_keygen()
        doc = create_did_document(did, kp.public_key)
        assert isinstance(doc, DIDDocument)

    def test_did_document_has_required_fields(self):
        did = generate_did()
        from shared.falcon_utils import falcon_keygen

        kp = falcon_keygen()
        doc = create_did_document(did, kp.public_key)
        assert doc.did == did
        assert doc.public_key == kp.public_key
        assert doc.created_at > 0
        assert doc.active is True

    def test_did_document_serialization(self):
        did = generate_did()
        from shared.falcon_utils import falcon_keygen

        kp = falcon_keygen()
        doc = create_did_document(did, kp.public_key)
        data = doc.to_dict()
        assert "did" in data
        assert "public_key" in data
        assert "created_at" in data
        assert "active" in data

    def test_did_document_from_dict_roundtrip(self):
        did = generate_did()
        from shared.falcon_utils import falcon_keygen

        kp = falcon_keygen()
        doc = create_did_document(did, kp.public_key)
        data = doc.to_dict()
        doc2 = DIDDocument.from_dict(data)
        assert doc2.did == doc.did
        assert doc2.public_key == doc.public_key
        assert doc2.created_at == doc.created_at


class TestDIDConversion:
    """Test DID <-> bytes32 conversion for Solidity compatibility."""

    def test_did_to_bytes32(self):
        did = generate_did()
        b32 = did_to_bytes32(did)
        assert isinstance(b32, bytes)
        assert len(b32) == 32

    def test_bytes32_to_did(self):
        did = generate_did()
        b32 = did_to_bytes32(did)
        recovered = bytes32_to_did(b32)
        assert recovered == did

    def test_did_bytes32_roundtrip(self):
        for _ in range(10):
            did = generate_did()
            assert bytes32_to_did(did_to_bytes32(did)) == did

    def test_bytes32_to_did_unregistered_raises(self):
        import hashlib

        fake_b32 = hashlib.sha256(b"nonexistent-did").digest()
        with pytest.raises(DIDNotFoundError):
            bytes32_to_did(fake_b32)


class TestDIDRegistry:
    """Test DID registry management."""

    def test_register_and_unregister(self):
        did = generate_did()
        b32 = register_did(did)
        assert bytes32_to_did(b32) == did
        unregister_did(did)
        with pytest.raises(DIDNotFoundError):
            bytes32_to_did(b32)

    def test_unregister_nonexistent_raises(self):
        with pytest.raises(DIDNotFoundError):
            unregister_did("did:falconiot:nonexistent")

    def test_clear_registry(self):
        did = generate_did()
        did_to_bytes32(did)
        clear_registry()
        import hashlib

        fake_b32 = hashlib.sha256(b"anything").digest()
        with pytest.raises(DIDNotFoundError):
            bytes32_to_did(fake_b32)


class TestDIDVerification:
    """Test DID document verification."""

    def test_verify_valid_document(self):
        did = generate_did()
        from shared.falcon_utils import falcon_keygen

        kp = falcon_keygen()
        doc = create_did_document(did, kp.public_key)
        assert verify_did_document(doc) is True

    def test_verify_deactivated_document(self):
        did = generate_did()
        from shared.falcon_utils import falcon_keygen

        kp = falcon_keygen()
        doc = create_did_document(did, kp.public_key)
        doc.active = False
        assert verify_did_document(doc) is False

    def test_verify_document_empty_public_key(self):
        did = generate_did()
        doc = create_did_document(did, b"")
        assert verify_did_document(doc) is False

    def test_verify_document_empty_did(self):
        doc = create_did_document("", b"\x00" * 32)
        assert verify_did_document(doc) is False

    def test_verify_document_invalid_did_prefix(self):
        doc = create_did_document("not-a-did", b"\x00" * 32)
        assert verify_did_document(doc) is False
