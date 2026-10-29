"""Per-device secrets. The Observe fingerprint key and the pseudonym key are random per device;
a constant key would make fingerprints reversible by anyone who reads the source."""

import os


def new_device_key() -> bytes:
    return os.urandom(32)
