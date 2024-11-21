Here is a translation of the Java code into equivalent Python code:

```Python
import os
from abc import ABCMeta, abstractmethod


class ProjectArchiveExporter:
    NAME = "Ghidra Data Type File"

    def __init__(self):
        super().__init__()
        self.name = self.NAME
        self.extension = ".ghidradatatypefile"
        self.options = []

    @abstractmethod
    def export(self, file_path: str, domain_obj, addr_set_view, monitor=None) -> bool:
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
            with open(file_path, 'wb') as f:
                domain_obj.save_to_packed_file(f, monitor)
        except Exception as e:
            print("Unexpected exception exporting file: ", str(e))
            return False
        return True

    def get_options(self) -> list:
        return []

    def set_options(self, options):
        pass  # this exporter doesn't support any options


class DomainObject(metaclass=ABCMeta):

    @abstractmethod
    def save_to_packed_file(self, file_path: str, monitor=None) -> None:
        pass

```

Please note that Python does not have direct equivalent of Java's `CancelledException` and `UnsupportedOperationException`. I've used a simple try-except block to handle any exceptions. Also, the abstract methods in the code are marked with `@abstractmethod`, which is specific to Python 3.4+.