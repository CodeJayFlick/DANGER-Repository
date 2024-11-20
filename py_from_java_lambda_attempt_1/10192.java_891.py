Here is a translation of the Java interface `MessageDigest` into Python:

```Python
class MessageDigest:
    def __init__(self):
        pass

    def get_algorithm(self) -> str:
        # TO DO: implement this method
        raise NotImplementedError("Method not implemented")

    def get_digest_length(self) -> int:
        # TO DO: implement this method
        raise NotImplementedError("Method not implemented")

    def update(self, input: bytes):
        # TO DO: implement this method
        raise NotImplementedError("Method not implemented")

    def update(self, input: int):
        # TO DO: implement this method
        raise NotImplementedError("Method not implemented")

    def update(self, input: long):
        # TO DO: implement this method
        raise NotImplementedError("Method not implemented")

    def update(self, input: bytes) -> None:
        # TO DO: implement this method
        raise NotImplementedError("Method not implemented")

    def update(self, input: bytes, offset: int, length: int) -> None:
        # TO DO: implement this method
        raise NotImplementedError("Method not implemented")

    def digest(self) -> bytes:
        # TO DO: implement this method
        raise NotImplementedError("Method not implemented")

    def digest_long(self) -> long:
        # TO DO: implement this method
        raise NotImplementedError("Method not implemented")

    def digest(self, buf: bytearray, offset: int, length: int) -> int:
        # TO DO: implement this method
        raise NotImplementedError("Method not implemented")

    def reset(self):
        pass

```

This Python code defines a class `MessageDigest` with the same methods as the Java interface. The implementation of these methods is left to you.

Note that in Python, we don't have an equivalent concept like Java's interfaces or abstract classes. Instead, we use inheritance and polymorphism to achieve similar results.