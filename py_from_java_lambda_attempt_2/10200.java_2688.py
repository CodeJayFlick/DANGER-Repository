Here is the translation of the Java code to Python:
```
class NullWriter:
    def write(self, cbuf: bytes, off: int = 0, len: int = -1) -> None:
        pass

    def write(self, c: int) -> None:
        pass

    def write(self, cbuf: bytes) -> None:
        pass

    def write(self, str: str) -> None:
        pass

    def write(self, str: str, off: int = 0, len: int = -1) -> None:
        pass

    def append(self, csq: str) -> 'NullWriter':
        return self

    def append(self, csq: str, start: int, end: int) -> 'NullWriter':
        return self

    def append(self, c: chr) -> 'NullWriter':
        return self

    def flush(self) -> None:
        pass

    def close(self) -> None:
        pass
```
Note that I've used Python 3.x syntax and type hints. Also, since the Java code is a simple stub implementation of the `Writer` interface, the Python translation is similarly straightforward - just define methods with the same signature as in the original Java code, but without any actual implementation.