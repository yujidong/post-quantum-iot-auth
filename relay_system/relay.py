"""
Relay node module for Experiment 3.
The relay node submits verified meta-transactions to the blockchain.
"""
import time

from relay_system.iot_client import SimulatedBlockchain


class RelayNode:
    """
    Relay node that submits verified transactions to the blockchain.
    Models the gas cost and latency of meta-transaction submission.
    """

    def __init__(self, relay_id: str, blockchain: SimulatedBlockchain):
        self.relay_id = relay_id
        self.blockchain = blockchain
        self._submitted_count = 0

    def submitted_count(self) -> int:
        return self._submitted_count

    def submit_verified_transaction(
        self,
        device_did: str,
        data_hash: str,
        signature: bytes,
        verified: bool,
        return_metrics: bool = False,
    ) -> str | dict:
        """
        Submit a verified transaction to the blockchain.
        Returns the transaction hash, or full metrics if return_metrics=True.
        """
        start = time.perf_counter()

        tx_hash = self.blockchain.submit_meta_transaction(
            relay_address=self.relay_id,
            data_hash=data_hash,
            signature_size=len(signature),
            did_active=verified,
        )

        total_latency = (time.perf_counter() - start) * 1000  # ms
        self._submitted_count += 1

        if return_metrics:
            receipt = self.blockchain.get_receipt(tx_hash)
            return {
                "tx_hash": tx_hash,
                "total_latency_ms": total_latency + receipt["latency_ms"],
                "gas_used": receipt["gas_used"],
                "block_number": receipt["block_number"],
            }
        return tx_hash

    def submit_batch(self, batch: list[dict], signatures: list[bytes]) -> list[str]:
        """Submit a batch of verified transactions to the blockchain."""
        tx_hashes = []
        for item, sig in zip(batch, signatures):
            tx_hash = self.submit_verified_transaction(
                device_did=item["device_did"],
                data_hash=item["data_hash"],
                signature=sig,
                verified=item["verified"],
            )
            tx_hashes.append(tx_hash)
        return tx_hashes

    def submit_batch_with_metrics(
        self, batch: list[dict], signatures: list[bytes]
    ) -> list[dict]:
        """Submit a batch and return metrics for each transaction."""
        results = []
        for item, sig in zip(batch, signatures):
            result = self.submit_verified_transaction(
                device_did=item["device_did"],
                data_hash=item["data_hash"],
                signature=sig,
                verified=item["verified"],
                return_metrics=True,
            )
            results.append(result)
        return results
