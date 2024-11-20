Here is the translation of the Java code to Python:
```
class FNV1a64MessageDigestFactory:
    def create_digest(self):
        from . import fnv1a64_message_digest
        return fnv1a64_message_digest.FNV1a64MessageDigest()
```
Note that I'm assuming you have a separate file `fnv1a64_message_digest.py` containing the implementation of the `FNV1a64MessageDigest` class. If not, please let me know and I can help with that as well!