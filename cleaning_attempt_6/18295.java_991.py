import io

class TsFileInput:
    def size(self):
        raise NotImplementedError("Method 'size' must be implemented")

    def position(self):
        raise NotImplementedError("Method 'position' must be implemented")

    def seek(self, new_position: int) -> None:
        raise NotImplementedError("Method 'seek' must be implemented")

    def read(self, buffer_size: int = 1024*1024) -> bytes:
        raise NotImplementedError("Method 'read' must be implemented")

    def read_at(self, position: int, buffer_size: int = 1024*1024) -> (int, bytes):
        raise NotImplementedError("Method 'read_at' must be implemented")

    def read_byte(self) -> int:
        raise NotImplementedError("Method 'read_byte' must be implemented")

    def read_bytes(self, b: bytearray, off: int, len: int) -> None:
        raise NotImplementedError("Method 'read_bytes' must be implemented")

    def wrap_as_file_channel(self):
        raise NotImplementedError("Method 'wrap_as_file_channel' must be implemented")

    def wrap_as_input_stream(self):
        raise NotImplementedError("Method 'wrap_as_input_stream' must be implemented")

    def close(self) -> None:
        raise NotImplementedError("Method 'close' must be implemented")

    def read_int(self) -> int:
        raise NotImplementedError("Method 'read_int' must be implemented")

    def read_varint_string(self, offset: int) -> str:
        raise NotImplementedError("Method 'read_varint_string' must be implemented")
