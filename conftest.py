"""
Pytest configuration — runs before any test collection.
"""

import pytest


@pytest.fixture(autouse=True)
def _clean_did_registry():
    """Clear the DID registry before and after each test for isolation."""
    from shared.did_utils import clear_registry

    clear_registry()
    yield
    clear_registry()
