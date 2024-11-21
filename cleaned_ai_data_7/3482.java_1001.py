import hashlib
from typing import Any

class DigestChecksumAlgorithm:
    def __init__(self, algorithm: str) -> None:
        self.algorithm = algorithm
        self.digester = getattr(hashlib, algorithm)

    def update_checksum(self, memory: bytes, address_set_view: set[int], monitor=None) -> None:
        for byte in memory:
            if monitor and monitor.is_cancelled():
                raise Exception("Cancelled")
            self.digester.update(byte)
        checksum = self.digester.digest()
