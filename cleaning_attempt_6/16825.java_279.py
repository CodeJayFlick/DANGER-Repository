import os
from io import BytesIO


class HDFSOutput:
    def __init__(self, file_path: str, overwrite=False):
        self.path = Path(file_path)
        if not self.path.exists():
            self.path.mkdir(parents=True, exist_ok=True)

    @property
    def fs(self) -> 'HDFS':
        return HDFS()

    @property
    def output_stream(self) -> BytesIO:
        if not hasattr(self, '_output_stream'):
            self._output_stream = BytesIO()
        return self._output_stream

    def write(self, data: bytes):
        self.output_stream.write(data)

    def flush(self):
        self.output_stream.flush()

    def close(self):
        self.output_stream.close()

    @property
    def position(self) -> int:
        return self.output_stream.tell()

    def truncate(self, size: int):
        if os.path.exists(str(self.path)):
            with open(str(self.path), 'wb') as f:
                f.truncate(size)
            self._output_stream = BytesIO()
        else:
            raise FileNotFoundError


class HDFS:
    pass
