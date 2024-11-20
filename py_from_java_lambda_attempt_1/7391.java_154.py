Here is the translation of the given Java code into Python:

```Python
import os
from io import BytesIO
from typing import List

class CrushedPNGFileSystem:
    def __init__(self, file_system_name: str, provider):
        self.file_system_name = file_system_name
        self.provider = provider

    def close(self) -> None:
        pass  # No equivalent in Python for closing a file system.

    def is_valid(self, monitor=None) -> bool:
        signature_length = len(CrushedPNGConstants.SIGNATURE_BYTES)
        signature_array = self.provider.read(signature_length)

        if bytes(signature_array) == CrushedPNGConstants.SIGNATURE_BYTES:
            inserted_chunk_id = self.provider.read(4)
            return bytes(inserted_chunk_id) == CrushedPNGConstants.INSERTED_IOS_CHUNK
        return False

    def open(self, monitor=None):
        reader = BinaryReader(BytesIO(self.provider), False)

        if monitor is not None:
            monitor.set_message("Opening iOS Crushed PNG...")

        self.png = ProcessedPNG(reader, monitor)
        uncrushed_png_filename = os.path.splitext(self.file_system_name)[0] + ".uncrusted.png"
        self.png_g_file = GFileImpl.from_filename(self, "root", uncrusted_png_filename, False, 1, None)

    def get_listing(self, directory=None) -> List[GFile]:
        if directory is not None and directory != self.root:
            return []
        else:
            return [self.png_g_file]

class FileAttributes:
    def __init__(self):
        pass

    def add(self, attr_type: str, value):
        # No equivalent in Python for adding file attributes.
        pass
```

Note that the `FileAttributes` class is not fully implemented as there seems to be no direct translation of Java's `FileAttributeType` and its usage.