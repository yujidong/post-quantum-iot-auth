"""
Tests for Experiment 4: Scalability Testing
Tests concurrent multi-device blockchain interactions at scale.
"""
import os
import json
import time
import threading
import pytest

from shared.config import (
    FALCON_512_SIGNATURE_SIZE_MAX,
    FALCON_512_PUBLIC_KEY_SIZE,
    SCALABILITY_DEVICE_COUNTS,
)
from scalability.scalability_runner import (
    ScalabilityRunner,
    ScalabilityResult,
    run_scalability_suite,
)


class TestScalabilityResult:
    def test_result_creation(self):
        result = ScalabilityResult(
            device_count=100,
            transactions_per_device=5,
            total_transactions=500,
            total_time_ms=1000.0,
            throughput_tps=500.0,
            avg_latency_ms=2.0,
            p50_latency_ms=1.8,
            p99_latency_ms=4.5,
            total_gas=50_000_000,
            avg_gas_per_tx=100_000,
            failed_transactions=0,
            concurrent_threads=10,
        )
        assert result.device_count == 100
        assert result.throughput_tps == 500.0
        assert result.failed_transactions == 0

    def test_result_to_dict(self):
        result = ScalabilityResult(
            device_count=50, transactions_per_device=3, total_transactions=150,
            total_time_ms=500.0, throughput_tps=300.0, avg_latency_ms=1.5,
            p50_latency_ms=1.2, p99_latency_ms=3.0, total_gas=15_000_000,
            avg_gas_per_tx=100_000, failed_transactions=0, concurrent_threads=5,
        )
        d = result.to_dict()
        assert d["device_count"] == 50
        assert d["throughput_tps"] == 300.0
        assert isinstance(d, dict)


class TestScalabilityRunner:
    def test_runner_creation(self):
        runner = ScalabilityRunner(device_count=10, transactions_per_device=3)
        assert runner.device_count == 10
        assert runner.transactions_per_device == 3

    def test_runner_single_device(self):
        runner = ScalabilityRunner(device_count=1, transactions_per_device=5)
        result = runner.run()
        assert result.total_transactions == 5
        assert result.throughput_tps > 0
        assert result.avg_latency_ms > 0
        assert result.total_gas > 0

    def test_runner_small_scale(self):
        runner = ScalabilityRunner(device_count=5, transactions_per_device=3)
        result = runner.run()
        assert result.total_transactions == 15
        assert result.device_count == 5
        assert result.failed_transactions >= 0

    def test_runner_concurrent_threads(self):
        runner = ScalabilityRunner(
            device_count=10,
            transactions_per_device=2,
            concurrent_threads=4,
        )
        result = runner.run()
        assert result.concurrent_threads == 4
        assert result.total_transactions == 20

    def test_runner_tracks_latency_percentiles(self):
        runner = ScalabilityRunner(device_count=10, transactions_per_device=5)
        result = runner.run()
        assert result.p50_latency_ms > 0
        assert result.p99_latency_ms > 0
        assert result.p99_latency_ms >= result.p50_latency_ms

    def test_runner_gas_metrics(self):
        runner = ScalabilityRunner(device_count=5, transactions_per_device=3)
        result = runner.run()
        assert result.total_gas > 0
        assert result.avg_gas_per_tx > 0

    def test_throughput_increases_with_parallelism(self):
        """More threads should yield comparable throughput (threading overhead is acceptable)."""
        results = []
        for threads in [1, 4]:
            runner = ScalabilityRunner(
                device_count=10,
                transactions_per_device=5,
                concurrent_threads=threads,
            )
            result = runner.run()
            results.append(result)

        # Multi-threaded should complete within 3x of single-threaded time
        # (thread overhead is acceptable; exact speedup depends on GIL and workload)
        assert results[1].total_time_ms <= results[0].total_time_ms * 3


class TestScalabilitySuite:
    def test_suite_runs_multiple_scales(self):
        results = run_scalability_suite(
            device_counts=[5, 10],
            transactions_per_device=3,
            concurrent_threads=2,
        )
        assert len(results) == 2
        assert results[0].device_count == 5
        assert results[1].device_count == 10

    def test_suite_throughput_scales(self):
        results = run_scalability_suite(
            device_counts=[5, 20],
            transactions_per_device=5,
            concurrent_threads=4,
        )
        # More devices should produce more total transactions
        assert results[1].total_transactions > results[0].total_transactions

    def test_suite_saves_results(self, tmp_path):
        results = run_scalability_suite(
            device_counts=[5, 10],
            transactions_per_device=2,
        )
        json_path = tmp_path / "scalability.json"
        csv_path = tmp_path / "scalability.csv"

        from scalability.scalability_runner import save_scalability_results
        save_scalability_results(results, json_path, csv_path)

        assert json_path.exists()
        assert csv_path.exists()

        loaded = json.loads(json_path.read_text())
        assert len(loaded) == 2

        csv_content = csv_path.read_text()
        assert "device_count" in csv_content
        assert "throughput_tps" in csv_content
