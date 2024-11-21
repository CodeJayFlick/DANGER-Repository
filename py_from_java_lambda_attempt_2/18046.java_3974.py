Here is the translation of the Java code to Python:
```
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
```
Note that I had to make some changes to the code to translate it to Python:

* In Java, `public` and `private` access modifiers are used to control visibility of methods. In Python, we don't have explicit access modifiers; instead, we use underscore prefixing (`_`) to indicate internal implementation details.
* In Java, `@Override` is used to indicate that a method overrides a parent class's method. In Python, this is not necessary because the concept of overriding does not exist in the same way as it does in Java.
* In Java, `throws IOException` is used to declare that a method may throw an exception. In Python, we use try-except blocks instead.

I hope this helps! Let me know if you have any further questions.