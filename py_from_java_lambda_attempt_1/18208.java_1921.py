Here is the translation of the Java code to Python:
```
# Apache License, Version 2.0 (see http://www.apache.org/licenses/LICENSE-2.0)

class FileOutputFactory:
    def get_ts_file_output(self, file_path: str, append: bool) -> 'TsFileOutput':
        # implement your logic here
        pass

from abc import ABC, abstractmethod


class TsFileOutput(ABC):
    @abstractmethod
    def write_to_file(self):  # todo: add implementation
        pass
```
Note that I've kept the `get_ts_file_output` method as an instance method in Python (i.e., it belongs to a class), whereas in Java, it was a static interface method. Also, I've defined an abstract base class (`TsFileOutput`) with an abstract method (`write_to_file`). You'll need to implement this method according to your specific requirements.

In the `get_ts_file_output` method, you can use Python's built-in file handling libraries (e.g., `open`, `os.path.join`) or any other relevant modules to create a TsFileOutput object.