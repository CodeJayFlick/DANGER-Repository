Here is the translation of the given Java code into equivalent Python:

```Python
import hashlib

class SHA384DigestChecksumAlgorithm:
    def __init__(self):
        super().__init__("SHA-384")

# Note: The 'super' function in Python doesn't work exactly like it does in Java.
# It's not necessary to use it here, but I kept it for consistency with the original code.

def main():
    algorithm = SHA384DigestChecksumAlgorithm()

if __name__ == "__main__":
    main()
```

This is a simple translation of your given Java code into Python. The `hashlib` library in Python provides functions for creating new hash objects and generating hashes from data.