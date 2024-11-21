import os
from io import BytesIO, BufferedRWPair


class LocalTsFileOutput:
    def __init__(self, file_path: str, append=False):
        self.file_path = file_path
        if not os.path.exists(file_path) or append:
            self.output_stream = open(file_path, 'ab')
        else:
            self.output_stream = open(file_path, 'wb')

    @property
    def buffered_stream(self):
        return BufferedRWPair(self.output_stream)

    def write(self, data: bytes) -> None:
        if isinstance(data, bytearray):
            data = bytes(data)
        self.buffered_stream.write(data)

    def close(self) -> None:
        try:
            self.output_stream.close()
        except Exception as e:
            print(f"Error closing file {self.file_path}: {str(e)}")

    @property
    def position(self) -> int:
        return self.output_stream.tell()

    def flush(self) -> None:
        self.buffered_stream.flush()

    def truncate(self, size: int) -> None:
        with open(self.file_path, 'r+b') as f:
            f.truncate(size)
