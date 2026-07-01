"""
Gateway module for Experiment 3.
The gateway aggregates IoT device data and performs off-chain Falcon verification
before forwarding verified data to the relay node.
"""
import hashlib
import time

from shared.falcon_utils import falcon_verify


class Gateway:
    """
    Edge gateway that collects IoT data, verifies Falcon-512 signatures
    off-chain, and prepares verified data batches for relay submission.
    """

    def __init__(self, gateway_id: str):
        self.gateway_id = gateway_id
        self._relayed_count = 0
        self._failed_count = 0
        self._batch: list[dict] = []

    def relayed_count(self) -> int:
        return self._relayed_count

    def failed_count(self) -> int:
        return self._failed_count

    def relay_data(
        self,
        device_did: str,
        device_pubkey: bytes,
        payload: bytes,
        signature: bytes,
    ) -> dict:
        """
        Receive data from an IoT device, verify the Falcon signature,
        and return the verification result with timing metrics.
        """
        start = time.perf_counter()
        verified = falcon_verify(payload, signature, device_pubkey)
        verify_time = (time.perf_counter() - start) * 1000  # ms

        data_hash = hashlib.sha256(payload).hexdigest()

        result = {
            "device_did": device_did,
            "data_hash": data_hash,
            "verified": verified,
            "verify_time_ms": verify_time,
            "gateway_id": self.gateway_id,
            "timestamp": time.time(),
            "payload_size": len(payload),
        }

        if verified:
            self._relayed_count += 1
            self._batch.append(result)
        else:
            self._failed_count += 1

        return result

    def get_batch(self) -> list[dict]:
        """Get the current batch of verified data and clear it."""
        batch = self._batch.copy()
        self._batch.clear()
        return batch

    def batch_size(self) -> int:
        return len(self._batch)
