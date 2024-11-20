Here is the translation of the Java code into Python:

```Python
import logging
from typing import List

class TsFileDeserializer:
    ERROR_MSG = "Unexpected data type: %s for Date TypeInfo: %s"

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        if not self.logger.hasHandlers():
            self.logger.addHandler(logging.StreamHandler())

    @staticmethod
    def deserialize(column_names: List[str], column_types: List[object], writable, device_id) -> list:
        if not isinstance(writable, dict):
            raise ValueError("Expecting a dictionary")

        row = []
        map_writable = writable

        for i in range(len(column_names)):
            column_type = column_types[i]
            column_name = column_names[i]
            data = map_writable.get(column_name)

            if data is None or isinstance(data, type(None)):
                row.append(None)
                continue

            if not hasattr(column_type, 'get_category'):
                raise ValueError("Unknown TypeInfo: " + str(column_type))

            category = getattr(column_type, 'get_category')()
            if category == 'PRIMITIVE':
                primitive_category = column_type.get_primitive_category()

                switcher = {
                    'BOOLEAN': lambda x: row.append(bool(x)),
                    'INT': lambda x: row.append(int(x)),
                    'LONG': lambda x: row.append(long(x)),
                    'FLOAT': lambda x: row.append(float(x)),
                    'DOUBLE': lambda x: row.append(float(x)),
                    'STRING': lambda x: row.append(str(x)),
                    'TIMESTAMP': lambda x: row.append(Timestamp.fromtimestamp(int(x)))
                }

                switcher.get(primitive_category, lambda x: raise ValueError("Unknown TypeInfo"))(data)

        return row
```

Note that the `TsFileSerDeException` is not directly translated into Python as it's a custom exception in Java. In this translation, I used Python's built-in exceptions (`ValueError`, `TypeError`) to handle errors instead of creating a new class for each type of error.

Also note that some parts of the code were simplified or removed because they are not necessary in Python (e.g., checking if an object is null).