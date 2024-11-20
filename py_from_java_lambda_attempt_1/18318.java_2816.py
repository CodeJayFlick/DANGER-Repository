Here is the translation of the Java code to Python:
```
import io

class PageHeaderV2:
    def __init__(self):
        pass  # equivalent to private constructor in Java

    @staticmethod
    def deserialize_from(input_stream: bytes, data_type: str) -> 'PageHeader':
        uncompressed_size = int.from_bytes(input_stream[:4], byteorder='little')
        compressed_size = int.from_bytes(input_stream[4:8], byteorder='little')

        statistics = StatisticsV2.deserialize(input_stream[8:], data_type)
        return PageHeader(uncompressed_size, compressed_size, statistics)

    @staticmethod
    def deserialize_from(buffer: memoryview, data_type: str) -> 'PageHeader':
        uncompressed_size = int.from_bytes(buffer[:4].tobytes(), byteorder='little')
        compressed_size = int.from_bytes(buffer[4:8].tobytes(), byteorder='little')

        statistics = StatisticsV2.deserialize(buffer[8:], data_type)
        return PageHeader(uncompressed_size, compressed_size, statistics)

class PageHeader:
    def __init__(self, uncompressed_size: int, compressed_size: int, statistics):
        self.uncompressed_size = uncompressed_size
        self.compressed_size = compressed_size
        self.statistics = statistics

class StatisticsV2:
    @staticmethod
    def deserialize(buffer: memoryview, data_type: str) -> 'Statistics':
        # implement deserialization logic here
        pass  # placeholder for now

from typing import TypeVar, Generic

T = TypeVar('T')

class Statistics(Generic[T]):
    pass  # abstract class, no implementation needed in this example
```
Note that I had to make some assumptions about the `StatisticsV2` and `Statistics` classes since their implementations were not provided. In a real-world scenario, you would need to implement these classes according to your specific requirements.

Also, Python does not have an exact equivalent of Java's `Serializable` interface or `IOException`. Instead, I used Python's built-in support for serializing/deserializing data using the `bytes` and `memoryview` types.