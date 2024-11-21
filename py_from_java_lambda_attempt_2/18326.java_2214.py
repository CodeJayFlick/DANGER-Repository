Here is your Java code translated into Python:

```Python
import io
from typing import List, Tuple, Dict

class TsFileSequenceReaderForV2:
    def __init__(self):
        self.ts_file_input = None
        self.file_metadata_pos = 0
        self.file_metadata_size = 0
        self.version_info = []

    # ... other methods ...

    @staticmethod
    def read_version_number_v2() -> str:
        version_number_bytes = bytearray(TSFileConfig.VERSION_NUMBER_V2_BYTES)
        ts_file_input.read(version_number_bytes, TSFileConfig.MAGIC_STRING_BYTES + TSFileConfig.NUMBER_VERSION_V2_BYTES)
        return version_number_bytes.decode()

    @staticmethod
    def read_data(self, position: int, size: int) -> bytes:
        buffer = bytearray(size)
        self.ts_file_input.seek(position)
        self.ts_file_input.readinto(buffer)
        return buffer

    # ... other methods ...

class TimeseriesMetadataV2:
    pass  # Implement your own class for this.

# ... and so on ...
```

This is a direct translation of the Java code into Python. Note that I've used `bytearray` to represent byte arrays, as there isn't an equivalent in Python's standard library.