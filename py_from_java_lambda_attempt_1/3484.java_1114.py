Here is the translation of the given Java code into Python:

```Python
import hashlib

class MD5DigestChecksumAlgorithm:
    def __init__(self):
        super().__init__()
```

Note that this Python code does not exactly match the original Java code. The main differences are:

1. In Python, we don't need to specify types for variables or method parameters.
2. We use `hashlib` module instead of `java.security.MessageDigest`.
3. There is no equivalent to Java's `extends DigestChecksumAlgorithm`. It seems that this class inherits from another one in the original code.

Here is a more complete Python version, with methods similar to those found in the original Java code:

```Python
import hashlib

class MD5DigestChecksumAlgorithm:
    def __init__(self):
        self.algorithm_name = "MD5"

    def get_algorithm_name(self):
        return self.algorithm_name

# Example usage:
md5_checksum_algorithm = MD5DigestChecksumAlgorithm()
print(md5_checksum_algorithm.get_algorithm_name())  # Output: MD5
```