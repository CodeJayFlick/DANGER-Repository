import io

class YAFFS2Buffer:
    record_size = None
    in_stream = None
    out_stream = None
    record_buffer = bytearray()

    def __init__(self, in_stream):
        self.in_stream = in_stream
        self.out_stream = None
        self.initialize(self.record_size)

    def initialize(self, record_size):
        self.record_size = record_size
        self.record_buffer = bytearray(record_size)

    def read_record(self) -> bytes:
        if not self.in_stream:
            raise IOError("input buffer is closed")
        num_bytes = self.in_stream.readinto(self.record_buffer)
        if num_bytes == -1:
            return None
        return self.record_buffer

    def skip(self, num_to_skip: int) -> int:
        try:
            return self.in_stream.seek(num_to_skip)
        except IOError as e:
            raise e

    def is_eof_record(self, record: bytes) -> bool:
        for i in range(len(record)):
            if record[i] != 0:
                return False
        return True

    def get_record_size(self):
        return self.record_size

    def close(self):
        try:
            if not (self.in_stream is io.TextIOWrapper(sys.stdin, encoding='utf-8')):
                self.in_stream.close()
        except IOError as e:
            raise e
        self.in_stream = None
