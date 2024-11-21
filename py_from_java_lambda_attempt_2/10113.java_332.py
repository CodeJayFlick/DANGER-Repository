Here is the translation of the Java code to Python:

```Python
import io
from zipfile import ZipFile, ZIPEntryInfo
from typing import Union

class ItemDeserializer:
    MAGIC_NUMBER = 1234567890
    FORMAT_VERSION = 1
    ZIP_ENTRY_NAME = "item"

    def __init__(self, packed_file: str) -> None:
        self.in = io.open(packed_file, 'rb')
        self.item_name = ''
        self.content_type = ''
        self.file_type = 0
        self.length = 0

    def deserialize(self) -> None:
        try:
            obj_in = io.BytesIO()
            obj_in.write(self.MAGIC_NUMBER.to_bytes(4, byteorder='little'))
            obj_in.write(self.FORMAT_VERSION.to_bytes(4, byteorder='little'))
            self.item_name = obj_in.read_string().decode('utf-8')
            self.content_type = obj_in.read_string().decode('utf-8') or None
            self.file_type = int.from_bytes(obj_in.read(4), 'little', signed=False)
            self.length = int.from_bytes(obj_in.read(8), 'little', signed=True)

        except Exception as e:
            raise ValueError("Invalid item data") from e

    def get_item_name(self) -> str:
        return self.item_name

    def get_content_type(self) -> Union[str, None]:
        return self.content_type

    def get_file_type(self) -> int:
        return self.file_type

    def get_length(self) -> int:
        return self.length

    def save_item(self, out: io.IOBase, monitor=None) -> None:
        if hasattr(out, 'write'):
            zip_in = ZipFile(self.in)
            entry = zip_in.getentry(ZIP_ENTRY_NAME)
            item_in = zip_in.open(entry)

            if monitor is not None:
                monitored_stream = io.BytesIO()
                with io.copyfileobj(item_in, monitored_stream) as f:
                    while True:
                        chunk = f.read(1024 * 8)
                        out.write(chunk)
                        if len(chunk) < 1024 * 8:
                            break
            else:
                while item_in.peek() > 0:
                    chunk = item_in.read(1024 * 8)
                    out.write(chunk)

    def __del__(self):
        self.dispose()

    def dispose(self) -> None:
        if hasattr(self.in, 'close'):
            try:
                self.in.close()
            except Exception as e:
                pass
```

Please note that Python does not have a direct equivalent of Java's `finalize()` method. The closest thing is the `__del__` special method which gets called when an object is garbage collected.