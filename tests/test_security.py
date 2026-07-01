"""
Tests for Experiment 5: Security Analysis — Implementation Correctness Validation.

Validates security properties through structured testing and formal analysis.
"""

import pytest

from security.attack_simulation import (
    run_all_security_tests,
    test_falcon_forgery_resistance as _falcon_forgery,
    test_ecdsa_forgery_resistance as _ecdsa_forgery,
    test_replay_resistance as _replay,
    test_timestamp_based_replay as _timestamp_replay,
    test_did_deactivation as _did_deactivation,
    test_key_rotation as _key_rotation,
    test_malicious_relay_rejection as _malicious_relay,
    test_empty_signature_rejection as _empty_sig,
    test_formal_security_properties as _formal_props,
    test_relay_trust_model as _relay_trust,
    SecurityTestResult,
)


class TestSignatureForgery:
    """Test that forged signatures are rejected."""

    def test_falcon_forgery_resistance(self):
        result = _falcon_forgery()
        assert isinstance(result, SecurityTestResult)
        assert result.passed, f"Falcon forgery test failed: {result.details}"

    def test_ecdsa_forgery_resistance(self):
        result = _ecdsa_forgery()
        assert isinstance(result, SecurityTestResult)
        assert result.passed, f"ECDSA forgery test failed: {result.details}"


class TestReplayAttack:
    """Test that replay attacks are detected."""

    def test_nonce_replay_resistance(self):
        result = _replay()
        assert isinstance(result, SecurityTestResult)
        assert result.passed, f"Replay resistance failed: {result.details}"

    def test_timestamp_replay_resistance(self):
        result = _timestamp_replay()
        assert isinstance(result, SecurityTestResult)
        assert result.passed, f"Timestamp replay failed: {result.details}"


class TestKeyCompromise:
    """Test key compromise recovery mechanisms."""

    def test_did_deactivation(self):
        result = _did_deactivation()
        assert isinstance(result, SecurityTestResult)
        assert result.passed, f"DID deactivation failed: {result.details}"

    def test_key_rotation(self):
        result = _key_rotation()
        assert isinstance(result, SecurityTestResult)
        assert result.passed, f"Key rotation failed: {result.details}"


class TestMaliciousRelay:
    """Test malicious relay behavior detection."""

    def test_malicious_relay_rejection(self):
        result = _malicious_relay()
        assert isinstance(result, SecurityTestResult)
        assert result.passed, f"Malicious relay test failed: {result.details}"

    def test_empty_signature_rejection(self):
        result = _empty_sig()
        assert isinstance(result, SecurityTestResult)
        assert result.passed, f"Empty signature test failed: {result.details}"


class TestFormalSecurity:
    """Test formal security properties."""

    def test_formal_security_properties(self):
        result = _formal_props()
        assert isinstance(result, SecurityTestResult)
        assert result.passed, f"Formal security test failed: {result.details}"

    def test_relay_trust_model(self):
        result = _relay_trust()
        assert isinstance(result, SecurityTestResult)
        assert result.passed, f"Relay trust model test failed: {result.details}"


class TestThreatModel:
    """Test threat model documentation."""

    def test_threat_model_structure(self):
        from security.threat_model import get_threat_model
        tm = get_threat_model()
        assert "threat_actors" in tm
        assert "security_guarantees" in tm
        assert "known_limitations" in tm
        assert "security_comparison" in tm

    def test_threat_model_actors(self):
        from security.threat_model import get_threat_model
        tm = get_threat_model()
        actors = tm["threat_actors"]
        assert len(actors) >= 4  # Classical, Quantum, Malicious Relay, Compromised Device
        actor_names = [a["name"] for a in actors]
        assert "Quantum Adversary" in actor_names
        assert "Malicious Relay" in actor_names

    def test_threat_model_quantum_comparison(self):
        from security.threat_model import get_threat_model
        tm = get_threat_model()
        comp = tm["security_comparison"]
        assert comp["this_work"]["quantum_safe"] is True
        assert comp["ecdsa_baseline"]["quantum_safe"] is False

    def test_threat_model_summary(self):
        from security.threat_model import get_threat_model_summary
        summary = get_threat_model_summary()
        assert "THREAT MODEL" in summary
        assert "Falcon-512" in summary
        assert "QUANTUM SAFETY" in summary


class TestSecuritySuite:
    """Run full security test suite."""

    def test_all_security_tests_pass(self):
        results = run_all_security_tests()
        assert len(results) > 0, "No security tests ran"

        failed = [r for r in results if not r.passed]
        assert len(failed) == 0, (
            f"{len(failed)}/{len(results)} security tests failed:\n"
            + "\n".join(f"  - {r.test_name}: {r.details}" for r in failed)
        )

    def test_security_test_result_format(self):
        result = _falcon_forgery()
        d = result.to_dict()
        assert "test_name" in d
        assert "category" in d
        assert "passed" in d
        assert "description" in d
        assert "execution_time_ms" in d
