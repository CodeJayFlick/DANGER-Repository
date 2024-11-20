import io


class WriteLogNode:
    def __init__(self):
        pass

    def write(self, plan: bytes) -> None:
        raise NotImplementedError("Subclasses must implement this method")

    def close(self) -> None:
        raise NotImplementedError("Subclasses must implement this method")

    def force_sync(self) -> None:
        raise NotImplementedError("Subclasses must implement this method")

    def notify_start_flush(self) -> None:
        raise NotImplementedError("Subclasses must implement this method")

    def notify_end_flush(self) -> None:
        pass

    @property
    def identifier(self):
        raise NotImplementedError("Subclasses must implement this property")

    @property
    def log_directory(self):
        raise NotImplementedError("Subclasses must implement this property")

    def delete(self) -> bytes:
        raise NotImplementedError("Subclasses must implement this method")

    def get_log_reader(self) -> io.IOBase:
        raise NotImplementedError("Subclasses must implement this method")

    def init_buffer(self, byte_buffers: list[bytes]) -> None:
        pass
