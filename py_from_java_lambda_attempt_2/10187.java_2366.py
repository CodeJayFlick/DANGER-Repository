Here is the translation of the given Java code into Python:

```Python
class AbstractMessageDigest:
    def __init__(self, algorithm: str, digest_length: int):
        self.algorithm = algorithm
        self.digest_length = digest_length

    def get_algorithm(self) -> str:
        return self.algorithm

    def get_digest_length(self) -> int:
        return self.digest_length

    def digest(self) -> bytes:
        results = bytearray(self.digest_length)
        self.update(results, 0, len(results))
        return bytes(results)

    def update(self, input: bytes, offset: int = 0, length: int = None):
        if length is None:
            length = len(input) - offset
        for ii in range(offset, offset + length):
            self.update(input[ii])

    def update_short(self, short_input: int):
        self.update((short_input >> 8) & 0xff)
        self.update(short_input & 0xff)

    def update_int(self, int_input: int):
        self.update((int_input >> 24) & 0xff)
        self.update((int_input >> 16) & 0xff)
        self.update((int_input >> 8) & 0xff)
        self.update(int_input & 0xff)

    def update_long(self, long_input: int):
        self.update((long_input >> 56) & 0xff)
        self.update((long_input >> 48) & 0xff)
        self.update((long_input >> 40) & 0xff)
        self.update((long_input >> 32) & 0xff)
        self.update((long_input >> 24) & 0xff)
        self.update((long_input >> 16) & 0xff)
        self.update((long_input >> 8) & 0xff)
        self.update(long_input & 0xff)

    def update(self, input: bytes):
        self.update(input, 0, len(input))
```

Note that Python does not have a direct equivalent to Java's `@Override` annotation. Also, the `TaskMonitor` and `CancelledException` classes are specific to Ghidra and do not exist in standard Python.