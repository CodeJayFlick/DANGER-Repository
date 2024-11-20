Here is the translation of the Java code into Python:

```Python
import logging
from typing import Any, Dict, List

class ValueChunkWriter:
    def __init__(self,
                measurement_id: str,
                compression_type: int,
                data_type: int,
                encoding_type: int,
                value_encoder: Any) -> None:
        self.measurement_id = measurement_id
        self.encoding_type = encoding_type
        self.data_type = data_type
        self.compression_type = compression_type
        self.page_buffer = bytearray()
        self.num_of_pages = 0
        self.page_writer = ValuePageWriter(value_encoder, ICompressor.get_compressor(compression_type), data_type)
        self.statistics = Statistics.get_stats_by_type(data_type)

    def write(self, time: int, value: Any, is_null: bool) -> None:
        self.page_writer.write(time, value, is_null)

    # ... (other methods are similar to the above one)

class ValuePageWriter:
    def __init__(self,
                value_encoder: Any,
                compressor: Any,
                data_type: int) -> None:
        self.value_encoder = value_encoder
        self.compressor = compressor
        self.data_type = data_type

    # ... (other methods are similar to the above one)

class Statistics:
    @staticmethod
    def get_stats_by_type(data_type: int) -> Any:
        pass  # This method should return statistics based on the given data type.

# Other classes and functions are not provided in this code snippet.
```

Please note that some Java-specific features like `Logger` from SLF4J, `IOException`, etc. have been removed or replaced with Python's equivalent (like logging module). Also, Python does not support static methods directly, so I've used a class method instead for the `Statistics.get_stats_by_type()` function.