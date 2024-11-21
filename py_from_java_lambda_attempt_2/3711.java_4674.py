Here is the translation of the Java code into Python:

```Python
import os
from abc import ABC, abstractmethod


class FileArchive(ABC):
    def __init__(self, archive_manager: 'DataTypeManagerHandler', file_path: str) -> None:
        self.archive_file = ResourceFile(file_path)
        self.has_write_lock = True
        self.changed = False
        self.archive_manager = archive_manager

    @abstractmethod
    def get_name(self) -> str:
        pass


class DataTypeFileManager(ABC):
    def __init__(self, file_path: str) -> None:
        self.file_path = file_path
        self.name = os.path.basename(file_path)

    def is_changed(self) -> bool:
        return False

    @abstractmethod
    def save_as(self, new_file_path: str) -> None:
        pass


class ArchiveCategoryChangeListener(ABC):
    def category_added(self, dtm: 'DataTypeManager', path: 'CategoryPath') -> None:
        # set changed to True
        pass

    def category_removed(self, dtm: 'DataTypeManager', path: 'CategoryPath') -> None:
        # set changed to True
        pass


class FileArchiveImpl(FileArchive):
    def __init__(self, archive_manager: 'DataTypeManagerHandler', file_path: str) -> None:
        super().__init__(archive_manager, file_path)
        self.file_data_type_manager = FileDataTypeManager(file_path)

    def get_name(self) -> str:
        return self.name

    def close(self) -> None:
        if not self.is_closed():
            self.file_data_type_manager.close()
            self.archive_file = None
            self.has_write_lock = False

    def delete(self) -> None:
        # implement deletion logic here
        pass


class ResourceFile(ABC):
    def __init__(self, file_path: str) -> None:
        self.file_path = file_path

    @abstractmethod
    def get_canonical_file(self) -> 'os.PathLike[str]':
        pass


class CategoryPath(ABC):
    # implement category path logic here
    pass


class DataTypeManagerHandler(ABC):
    # implement data type manager handler logic here
    pass


# usage example:
archive_manager = DataTypeManagerHandler()
file_archive = FileArchiveImpl(archive_manager, 'path/to/file')
print(file_archive.get_name())
```

Please note that this is a translation of the Java code into Python and it might not be 100% equivalent. The reason for this is that some parts of the original code are missing (like `BuiltInArchive`, `ProgramArchive`, etc.) or were simplified to fit the Python syntax better.