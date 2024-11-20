import io

class TsFileOutput:
    def write(self, b: bytes) -> None:
        raise NotImplementedError("Subclasses must implement this method")

    def write(self, b: int) -> None:
        self.write(bytes([b]))

    def write(self, buffer: memoryview) -> None:
        self.write(buffer.tobytes())

    def get_position(self) -> int:
        raise NotImplementedError("Subclasses must implement this method")

    def close(self) -> None:
        raise NotImplementedError("Subclasses must implement this method")

    def wrap_as_stream(self) -> io.IOBase:
        raise NotImplementedError("Subclasses must implement this method")

    def flush(self) -> None:
        raise NotImplementedError("Subclasses must implement this method")

    def truncate(self, size: int) -> None:
        raise NotImplementedError("Subclasses must implement this method")
