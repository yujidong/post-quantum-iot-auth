"""
Tests for crypto_benchmark/benchmark.py — TDD tests.
"""

import json
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Add crypto_benchmark directory to path for direct module import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "crypto_benchmark"))

from benchmark import (
    BenchmarkResult,
    CryptoScheme,
    run_benchmark,
    run_full_benchmark_suite,
    save_results_csv,
    save_results_json,
)


class TestBenchmarkResult:
    """Test BenchmarkResult data class."""

    def test_result_creation(self):
        result = BenchmarkResult(
            scheme="Falcon-512",
            operation="sign",
            time_ns=1500000,
            memory_kb=256.0,
            message_size=256,
            key_size=897,
            signature_size=666,
            iteration=0,
            backend="simulation",
        )
        assert result.scheme == "Falcon-512"
        assert result.operation == "sign"
        assert result.time_ns == 1500000

    def test_result_time_ms(self):
        result = BenchmarkResult(
            scheme="ECDSA",
            operation="sign",
            time_ns=1_500_000,
            memory_kb=10.0,
            message_size=256,
            key_size=64,
            signature_size=64,
            iteration=0,
            backend="simulation",
        )
        assert result.time_ms == pytest.approx(1.5, abs=0.01)

    def test_result_to_dict(self):
        result = BenchmarkResult(
            scheme="Falcon-512",
            operation="verify",
            time_ns=2_000_000,
            memory_kb=300.0,
            message_size=256,
            key_size=897,
            signature_size=666,
            iteration=5,
            backend="simulation",
        )
        d = result.to_dict()
        assert d["scheme"] == "Falcon-512"
        assert d["time_ms"] == pytest.approx(2.0, abs=0.01)
        assert d["backend"] == "simulation"


class TestCryptoScheme:
    """Test CryptoScheme abstraction."""

    def test_falcon_scheme(self):
        scheme = CryptoScheme("Falcon-512")
        assert scheme.name == "Falcon-512"
        assert scheme.public_key_size > 0
        assert scheme.signature_size > 0

    def test_ecdsa_scheme(self):
        scheme = CryptoScheme("ECDSA")
        assert scheme.name == "ECDSA"
        assert scheme.public_key_size == 64

    def test_scheme_keygen(self):
        scheme = CryptoScheme("Falcon-512")
        pub, priv = scheme.keygen()
        assert len(pub) > 0
        assert len(priv) > 0

    def test_scheme_sign_verify(self):
        scheme = CryptoScheme("Falcon-512")
        pub, priv = scheme.keygen()
        message = b"test benchmark message"
        sig = scheme.sign(message, priv)
        assert scheme.verify(message, sig, pub) is True

    def test_scheme_sign_verify_ecdsa(self):
        scheme = CryptoScheme("ECDSA")
        pub, priv = scheme.keygen()
        message = b"test benchmark message"
        sig = scheme.sign(message, priv)
        assert scheme.verify(message, sig, pub) is True

    def test_scheme_all_supported(self):
        for name in ["Falcon-512", "ECDSA", "Dilithium2", "Dilithium3"]:
            scheme = CryptoScheme(name)
            pub, priv = scheme.keygen()
            sig = scheme.sign(b"test", priv)
            assert scheme.verify(b"test", sig, pub) is True

    def test_scheme_invalid_name_raises(self):
        with pytest.raises(ValueError, match="Unsupported scheme"):
            CryptoScheme("RSA-2048")

    def test_scheme_wrong_message_verify_fails(self):
        scheme = CryptoScheme("Falcon-512")
        pub, priv = scheme.keygen()
        sig = scheme.sign(b"original", priv)
        assert scheme.verify(b"tampered", sig, pub) is False

    def test_scheme_wrong_key_verify_fails(self):
        scheme1 = CryptoScheme("Falcon-512")
        scheme2 = CryptoScheme("Falcon-512")
        pub1, priv1 = scheme1.keygen()
        _, priv2 = scheme2.keygen()
        sig = scheme1.sign(b"test", priv1)
        pub2, _ = scheme2.keygen()
        assert scheme2.verify(b"test", sig, pub2) is False

    def test_ecdsa_key_and_sig_sizes(self):
        scheme = CryptoScheme("ECDSA")
        pub, priv = scheme.keygen()
        assert len(pub) == 64
        sig = scheme.sign(b"test", priv)
        assert len(sig) == 64

    def test_dilithium2_sizes(self):
        scheme = CryptoScheme("Dilithium2")
        pub, priv = scheme.keygen()
        assert len(pub) == 1312
        sig = scheme.sign(b"test", priv)
        assert len(sig) == 2420

    def test_dilithium3_sizes(self):
        scheme = CryptoScheme("Dilithium3")
        pub, priv = scheme.keygen()
        assert len(pub) == 1952
        sig = scheme.sign(b"test", priv)
        assert len(sig) == 3309


class TestRunBenchmark:
    """Test individual benchmark execution."""

    def test_run_benchmark_returns_list(self):
        scheme = CryptoScheme("Falcon-512")
        results = run_benchmark(scheme, iterations=10, message_size=256)
        assert isinstance(results, list)
        assert len(results) > 0

    def test_run_benchmark_correct_count(self):
        scheme = CryptoScheme("ECDSA")
        results = run_benchmark(scheme, iterations=5, message_size=256)
        # Should have results for keygen, sign, verify * iterations
        # Each iteration produces one result per operation
        operations = {r.operation for r in results}
        assert "keygen" in operations
        assert "sign" in operations
        assert "verify" in operations

    def test_run_benchmark_measures_time(self):
        scheme = CryptoScheme("ECDSA")
        results = run_benchmark(scheme, iterations=3, message_size=256)
        for r in results:
            assert r.time_ns > 0

    def test_run_benchmark_records_memory(self):
        scheme = CryptoScheme("ECDSA")
        results = run_benchmark(scheme, iterations=3, message_size=256)
        for r in results:
            assert r.memory_kb >= 0


class TestFullSuite:
    """Test full benchmark suite execution."""

    def test_full_suite_runs_all_schemes(self):
        results = run_full_benchmark_suite(
            schemes=["ECDSA"],
            iterations=5,
            message_size=256,
        )
        assert len(results) > 0
        schemes_found = {r.scheme for r in results}
        assert "ECDSA" in schemes_found

    def test_full_suite_multiple_schemes(self):
        results = run_full_benchmark_suite(
            schemes=["ECDSA", "Falcon-512"],
            iterations=3,
            message_size=256,
        )
        schemes_found = {r.scheme for r in results}
        assert "ECDSA" in schemes_found
        assert "Falcon-512" in schemes_found


class TestSaveResults:
    """Test result serialization."""

    def test_save_json(self):
        results = [
            BenchmarkResult(
                scheme="ECDSA",
                operation="sign",
                time_ns=1_000_000,
                memory_kb=10.0,
                message_size=256,
                key_size=64,
                signature_size=64,
                iteration=0,
                backend="simulation",
            )
        ]
        with tempfile.NamedTemporaryFile(
            suffix=".json", delete=False, mode="w"
        ) as f:
            path = f.name

        try:
            save_results_json(results, path)
            with open(path) as f:
                data = json.load(f)
            assert len(data) == 1
            assert data[0]["scheme"] == "ECDSA"
        finally:
            os.unlink(path)

    def test_save_csv(self):
        results = [
            BenchmarkResult(
                scheme="Falcon-512",
                operation="verify",
                time_ns=2_000_000,
                memory_kb=300.0,
                message_size=256,
                key_size=897,
                signature_size=666,
                iteration=0,
                backend="simulation",
            )
        ]
        with tempfile.NamedTemporaryFile(
            suffix=".csv", delete=False, mode="w"
        ) as f:
            path = f.name

        try:
            save_results_csv(results, path)
            with open(path) as f:
                content = f.read()
            assert "Falcon-512" in content
            assert "verify" in content
        finally:
            os.unlink(path)
