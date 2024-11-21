import thrift.transport.TTransport as TTransport
from xerial.snappy import Snappy

class TSnappyElasticFramedTransport(TTransport):
    def __init__(self, underlying=TTransport()):
        self._underlying = underlying

    @classmethod
    def Factory(cls):
        return cls.Factory()

    @classmethod
    def Factory(cls, thrift_default_buffer_size=0, thrift_max_frame_size=0):
        return super().Factory(thrift_default_buffer_size, thrift_max_frame_size)

    def get_transport(self, trans: TTransport) -> TTransport:
        return self

    def __init__(self, underlying=TTransport(), thrift_default_buffer_size=0, thrift_max_frame_size=0):
        super().__init__(underlying, thrift_default_buffer_size, thrift_max_frame_size)

    @staticmethod
    def uncompressed_length(buf: bytes, off: int, len: int) -> int:
        return Snappy.uncompressed_length(buf, off, len)

    @staticmethod
    def max_compressed_length(len: int) -> int:
        return Snappy.max_compressed_length(len)

    @staticmethod
    def compress(input: bytes, in_off: int, len: int, output: bytes, out_off: int) -> int:
        return Snappy.compress(input, in_off, len, output, out_off)

    @staticmethod
    def uncompress(input: bytes, in_off: int, size: int, output: bytes, out_off: int):
        Snappy.uncompress(input, in_off, size, output, out_off)
