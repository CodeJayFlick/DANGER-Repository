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
