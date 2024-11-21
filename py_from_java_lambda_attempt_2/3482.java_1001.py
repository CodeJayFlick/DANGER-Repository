Here is the translation of the given Java code into Python:

```Python
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
```

Please note that Python does not have direct equivalents of Java's MessageDigest or ChecksumAlgorithm classes. The hashlib library provides various hash algorithms, such as MD5, SHA1, and others.

In this translation:

- `MessageDigest` is replaced with the `hashlib` module.
- `updateChecksum` method now iterates over each byte in memory instead of using a MemoryByteIterator class.
- `CancelledException` has been replaced with Python's built-in exception mechanism.