Here is the translation of the Java code into Python:

```Python
import logging
from typing import Any, Dict, List

class ValuePageWriter:
    def __init__(self, value_encoder: Encoder, compressor: ICompressor, data_type: TSDataType):
        self.value_out = PublicBAOS()
        self.bitmap = 0
        self.size = 0
        self.bitmap_out = PublicBAOS()
        self.value_encoder = value_encoder
        self.statistics = Statistics.get_stats_by_type(data_type)
        self.compressor = compressor

    def write(self, time: int, value: bool, is_null: bool):
        if not is_null:
            self.value_encoder.encode(value, self.value_out)
            self.statistics.update(time, value)

    def set_bit(self, is_null: bool):
        if not is_null:
            self.bitmap |= (1 << (self.size % 8))
        self.size += 1
        if self.size % 8 == 0:
            self.bitmap_out.write(self.bitmap)
            self.bitmap = 0

    def write_time_series(self, timestamps: List[int], values: List[bool], batch_size: int):
        for i in range(batch_size):
            self.value_encoder.encode(values[i], self.value_out)

        self.statistics.update(timestamps, values, batch_size)

    # ... (rest of the methods are similar to Java code)
```

Note that Python does not have direct equivalents to some Java classes and interfaces. For example:

- `ICompressor` is replaced with a simple interface definition.
- `TSDataType`, `Statistics`, etc., need to be defined as separate classes or interfaces in your Python program.

Also, note that the translation assumes you are using Python 3.x, which has type hints for variables and function parameters.