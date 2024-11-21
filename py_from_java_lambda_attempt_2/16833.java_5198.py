Here's your Java code translated into Python:

```Python
import logging
from typing import Dict

class TSFRecordWriter:
    def __init__(self, job: dict, path: str, schema: dict) -> None:
        self.logger = logging.getLogger(__name__)
        self.writer = TsFileWriter(path, job['configuration'], False, schema)

    def write(self, key: int, value: Dict):
        try:
            self.writer.write(value)
        except WriteProcessException as e:
            raise Exception(f"Write tsfile record error {e}")

    def close(self) -> None:
        self.logger.info("Close the record writer")
        self.writer.close()

class TsFileWriter:
    def __init__(self, path: str, configuration: dict, overwrite: bool, schema: dict):
        pass

    def write(self, value: Dict) -> None:
        # implement your logic here
        pass

    def close(self) -> None:
        pass
```

Note that I've used Python's built-in `logging` module for logging. The Java code has a lot of dependencies and classes which are not easily translatable to Python, so some parts have been simplified or omitted in this translation.

Also note that the `TsFileWriter` class is just an interface with no implementation provided here. You would need to implement it according to your specific requirements.