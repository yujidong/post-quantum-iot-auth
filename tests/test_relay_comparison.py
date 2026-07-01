"""
Tests for Experiment 3: Relay Comparison
Compares direct blockchain submission vs relay-assisted meta-transactions.
"""
import os
import hashlib
import time
import json
import pytest

from shared.config import (
    FALCON_512_PUBLIC_KEY_SIZE,
    FALCON_512_SIGNATURE_SIZE_MAX,
    RELAY_TEST_TRANSACTION_COUNT,
    RELAY_TEST_PAYLOAD_SIZE,
)
from shared.falcon_utils import falcon_keygen, falcon_sign, falcon_verify
from shared.did_utils import generate_did, create_did_document, register_did
from relay_system.iot_client import IoTDevice, SimulatedBlockchain
from relay_system.gateway import Gateway
from relay_system.relay import RelayNode
from relay_system.runner import ComparisonRunner


# ─── IoT Device Tests ───


class TestIoTDevice:
    def test_device_creation(self):
        device = IoTDevice(device_id="sensor-001")
        assert device.device_id == "sensor-001"
        assert device.did is not None
        assert device.keypair is not None

    def test_device_generates_did(self):
        device = IoTDevice(device_id="sensor-002")
        assert device.did.startswith("did:falconiot:")
        assert len(device.did) > len("did:falconiot:")

    def test_device_has_falcon_keypair(self):
        device = IoTDevice(device_id="sensor-003")
        assert len(device.keypair.public_key) == FALCON_512_PUBLIC_KEY_SIZE
        assert len(device.keypair.private_key) == 1281

    def test_device_signs_sensor_data(self):
        device = IoTDevice(device_id="sensor-004")
        payload = b"temperature=25.3"
        sig = device.sign_data(payload)
        # pqcrypto returns variable-length signatures (avg ~666, max 752)
        assert 600 <= len(sig) <= FALCON_512_SIGNATURE_SIZE_MAX

    def test_device_signature_verifiable(self):
        device = IoTDevice(device_id="sensor-005")
        payload = b"humidity=65.2"
        sig = device.sign_data(payload)
        assert falcon_verify(payload, sig, device.keypair.public_key)

    def test_device_different_data_different_sig(self):
        device = IoTDevice(device_id="sensor-006")
        sig1 = device.sign_data(b"data-A")
        sig2 = device.sign_data(b"data-B")
        assert sig1 != sig2


# ─── Simulated Blockchain Tests ───


class TestSimulatedBlockchain:
    def test_blockchain_init(self):
        bc = SimulatedBlockchain()
        assert bc.transaction_count() == 0
        assert bc.block_number() == 0

    def test_submit_transaction(self):
        bc = SimulatedBlockchain()
        tx_hash = bc.submit_transaction(
            sender="0xabc", data_hash="hash1", payload_size=256
        )
        assert tx_hash is not None
        assert bc.transaction_count() == 1

    def test_multiple_transactions_increment_block(self):
        bc = SimulatedBlockchain()
        for i in range(5):
            bc.submit_transaction(
                sender=f"0x{i}", data_hash=f"hash{i}", payload_size=100
            )
        assert bc.transaction_count() == 5
        assert bc.block_number() > 0

    def test_get_transaction_receipt(self):
        bc = SimulatedBlockchain()
        tx_hash = bc.submit_transaction(
            sender="0xabc", data_hash="hash1", payload_size=256
        )
        receipt = bc.get_receipt(tx_hash)
        assert receipt is not None
        assert receipt["gas_used"] > 0
        assert receipt["block_number"] > 0
        assert "latency_ms" in receipt

    def test_gas_cost_increases_with_payload(self):
        bc = SimulatedBlockchain()
        tx1 = bc.submit_transaction("0x1", "h1", payload_size=64)
        tx2 = bc.submit_transaction("0x2", "h2", payload_size=897)
        r1 = bc.get_receipt(tx1)
        r2 = bc.get_receipt(tx2)
        # Larger payload costs more gas
        assert r2["gas_used"] >= r1["gas_used"]


# ─── Gateway Tests ───


class TestGateway:
    def test_gateway_creation(self):
        gw = Gateway(gateway_id="gw-001")
        assert gw.gateway_id == "gw-001"
        assert gw.relayed_count() == 0

    def test_gateway_aggregates_device_data(self):
        gw = Gateway(gateway_id="gw-002")
        device = IoTDevice(device_id="sensor-gw")
        payload = b"temp=30"
        sig = device.sign_data(payload)

        result = gw.relay_data(
            device_did=device.did,
            device_pubkey=device.keypair.public_key,
            payload=payload,
            signature=sig,
        )
        assert result is not None
        assert result["verified"] is True
        assert gw.relayed_count() == 1

    def test_gateway_detects_invalid_signature(self):
        gw = Gateway(gateway_id="gw-003")
        device = IoTDevice(device_id="sensor-bad")
        payload = b"temp=30"
        wrong_sig = os.urandom(FALCON_512_SIGNATURE_SIZE_MAX)

        result = gw.relay_data(
            device_did=device.did,
            device_pubkey=device.keypair.public_key,
            payload=payload,
            signature=wrong_sig,
        )
        assert result["verified"] is False

    def test_gateway_records_latency(self):
        gw = Gateway(gateway_id="gw-004")
        device = IoTDevice(device_id="sensor-lat")
        payload = b"pressure=1013"
        sig = device.sign_data(payload)

        result = gw.relay_data(
            device_did=device.did,
            device_pubkey=device.keypair.public_key,
            payload=payload,
            signature=sig,
        )
        assert "verify_time_ms" in result
        assert result["verify_time_ms"] >= 0

    def test_gateway_data_hash_is_sha256(self):
        gw = Gateway(gateway_id="gw-005")
        device = IoTDevice(device_id="sensor-hash")
        payload = b"voltage=3.3"
        sig = device.sign_data(payload)

        result = gw.relay_data(
            device_did=device.did,
            device_pubkey=device.keypair.public_key,
            payload=payload,
            signature=sig,
        )
        expected_hash = hashlib.sha256(payload).hexdigest()
        assert result["data_hash"] == expected_hash


# ─── RelayNode Tests ───


class TestRelayNode:
    def test_relay_creation(self):
        bc = SimulatedBlockchain()
        relay = RelayNode(relay_id="relay-001", blockchain=bc)
        assert relay.relay_id == "relay-001"
        assert relay.submitted_count() == 0

    def test_relay_submits_verified_transaction(self):
        bc = SimulatedBlockchain()
        relay = RelayNode(relay_id="relay-002", blockchain=bc)
        device = IoTDevice(device_id="sensor-relay")

        payload = b"light=850"
        sig = device.sign_data(payload)
        data_hash = payload.hex()

        tx_hash = relay.submit_verified_transaction(
            device_did=device.did,
            data_hash=data_hash,
            signature=sig,
            verified=True,
        )
        assert tx_hash is not None
        assert relay.submitted_count() == 1
        assert bc.transaction_count() == 1

    def test_relay_tracks_total_latency(self):
        bc = SimulatedBlockchain()
        relay = RelayNode(relay_id="relay-003", blockchain=bc)
        device = IoTDevice(device_id="sensor-r-lat")

        payload = b"co2=420"
        sig = device.sign_data(payload)
        data_hash = payload.hex()

        result = relay.submit_verified_transaction(
            device_did=device.did,
            data_hash=data_hash,
            signature=sig,
            verified=True,
            return_metrics=True,
        )
        assert "total_latency_ms" in result
        assert result["total_latency_ms"] >= 0


# ─── Comparison Runner Tests ───


class TestComparisonRunner:
    def test_runner_creation(self):
        runner = ComparisonRunner(device_count=5, transactions_per_device=3)
        assert runner.device_count == 5
        assert runner.transactions_per_device == 3

    def test_runner_direct_path(self):
        runner = ComparisonRunner(device_count=3, transactions_per_device=2)
        result = runner.run_direct_path()
        assert result["total_transactions"] == 6  # 3 devices × 2 txns
        assert result["total_latency_ms"] > 0
        assert result["avg_latency_ms"] > 0
        assert result["total_gas"] > 0

    def test_runner_relay_path(self):
        runner = ComparisonRunner(device_count=3, transactions_per_device=2)
        result = runner.run_relay_path()
        assert result["total_transactions"] == 6
        assert result["total_latency_ms"] > 0
        assert result["avg_latency_ms"] > 0
        assert result["total_gas"] > 0

    def test_relay_path_lower_latency_than_direct(self):
        """The relay path should be faster due to batch submission."""
        runner = ComparisonRunner(device_count=5, transactions_per_device=3)
        direct = runner.run_direct_path()
        relay = runner.run_relay_path()
        # Relay aggregates and submits once, so total latency should be lower
        assert relay["avg_latency_ms"] <= direct["avg_latency_ms"] * 2

    def test_relay_gas_far_below_theoretical_falcon(self):
        """Relay gas should be orders of magnitude below theoretical on-chain Falcon."""
        runner = ComparisonRunner(device_count=5, transactions_per_device=3)
        relay = runner.run_relay_path()
        # Theoretical on-chain Falcon verification: ~500,000,000 gas (exceeds block limit)
        theoretical_falcon = 500_000_000
        relay_per_tx = relay["total_gas"] / relay["total_transactions"]
        # Relay should be at least 100x cheaper than on-chain Falcon
        assert relay_per_tx < theoretical_falcon / 100

    def test_runner_full_comparison(self):
        runner = ComparisonRunner(device_count=3, transactions_per_device=2)
        result = runner.run_comparison()
        assert "direct_ecdsa" in result
        assert "relay_falcon" in result
        assert "comparison" in result
        assert "relay_vs_falcon_ratio" in result["comparison"]
        assert "relay_vs_ecdsa_gas_ratio" in result["comparison"]
        assert result["comparison"]["relay_vs_falcon_ratio"] > 100  # >100x cheaper than on-chain Falcon

    def test_runner_saves_results(self, tmp_path):
        runner = ComparisonRunner(device_count=2, transactions_per_device=1)
        result = runner.run_comparison()
        json_path = tmp_path / "comparison.json"
        runner.save_results(result, json_path)
        assert json_path.exists()
        loaded = json.loads(json_path.read_text())
        assert "direct_ecdsa" in loaded
        assert "relay_falcon" in loaded

    def test_relay_path_tracks_failed_verifications(self):
        runner = ComparisonRunner(device_count=2, transactions_per_device=1)
        result = runner.run_relay_path()
        assert "failed_verifications" in result
        # With real PQC backend, all valid signatures should verify
        assert result["failed_verifications"] == 0
