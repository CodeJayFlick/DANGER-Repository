Here is the translation of the Java code to Python:
```python
import io
from typing import Any

class PageReaderV2:
    def __init__(self,
                 page_data: bytes,
                 data_type: str,
                 value_decoder: Any,
                 time_decoder: Any,
                 filter: Any):
        pass  # constructor implementation omitted for brevity

    @staticmethod
    def get_all_satisfied_page_data(ascending: bool, page_header: Any = None) -> io.BytesIO:
        if data_type not in [b'INT32', b'TEXT']:
            return super().get_all_satisfied_page_data(ascending)

        page_data = BatchDataFactory.create_batch_data(data_type, ascending, False)
        time_buffer = time_decoder.get_next()

        while time_buffer is not None:
            timestamp = time_decoder.read_long(time_buffer)
            if data_type == b'INT32':
                an_int = value_decoder.read_int(value_buffer) if isinstance(value_decoder, PlainDecoder) else value_decoder.read_int(value_buffer)
                if not is_deleted(timestamp) and (filter is None or filter.satisfy(timestamp, an_int)):
                    page_data.put_int(timestamp, an_int)
            elif data_type == b'TEXT':
                length = value_buffer.get_int()
                buf = bytearray(length)
                value_buffer.get(buf, 0, len(buf))
                a_binary = Binary(buf)
                if not is_deleted(timestamp) and (filter is None or filter.satisfy(timestamp, a_binary)):
                    page_data.put_binary(timestamp, a_binary)
            else:
                raise UnSupportedDataTypeException(str(data_type))

        return page_data.flip()

class BatchDataFactory:
    @staticmethod
    def create_batch_data(data_type: str, ascending: bool, flip: bool) -> io.BytesIO:
        pass  # implementation omitted for brevity

class Binary:
    def __init__(self, buf: bytearray):
        self.buf = buf

    def get(self, offset: int, length: int) -> bytes:
        return self.buf[offset:length]

class Filter:
    @staticmethod
    def satisfy(timestamp: Any, value: Any) -> bool:
        pass  # implementation omitted for brevity

def is_deleted(timestamp: Any) -> bool:
    pass  # implementation omitted for brevity

# Example usage:
page_reader = PageReaderV2(b'page_data', b'TEXT', value_decoder=PlainDecoder(), time_decoder=time_decoder, filter=None)
batch_data = page_reader.get_all_satisfied_page_data(ascending=True)
```
Note that I've replaced the Java-specific types (e.g. `ByteBuffer`, `TSDataType`) with Python equivalents (e.g. `bytes`, `str`). Additionally, some methods and classes have been omitted or simplified for brevity's sake.