Here is the translation of the given Java code into equivalent Python:

```Python
import os

class FileDataTypeManager:
    EXTENSION = "gdt"
    SUFFIX = "." + EXTENSION
    OLD_EXTENSION = "dtf"
    OLD_SUFFIX = "." + OLD_EXTENSION

    def __init__(self, packed_dbfile: str, open_mode: int) -> None:
        super().__init__()
        self.file = ResourceFile(packed_dbfile)
        if not self.file.name.endswith(self.SUFFIX):
            raise ValueError("Archive files must end with " + self.SUFFIX)
        self.packed_DB = ((PackedDBHandle)(self.db_handle)).get_packed_database()
        self.name = os.path.splitext(os.path.basename(self.file.name))[0]

    @classmethod
    def create_file_archive(cls, packed_dbfile: str) -> 'FileDataTypeManager':
        return cls(packed_dbfile, DBConstants.CREATE)

    @classmethod
    def open_file_archive(cls, packed_dbfile: str, open_for_update: bool = False) -> 'FileDataTypeManager':
        if not isinstance(open_for_update, bool):
            raise ValueError("openForUpdate must be a boolean")
        return cls(packed_dbfile, DBConstants.READ_ONLY if not open_for_update else DBConstants.UPDATE)

    def save_as(self, save_file: str, new_universal_id: UniversalID) -> None:
        resource_save_file = ResourceFile(save_file)
        self.validate_filename(resource_save_file)
        try:
            packed_DB = ((PackedDBHandle)(self.db_handle)).save("DTArchive", os.path.dirname(save_file), 
                os.path.basename(save_file), new_universal_id.value, TaskMonitor.DUMMY)
            self.file = resource_save_file
            self.update_root_category_name(resource_save_file, self.get_root_category())
        except CancelledException:
            pass

    def save_as(self, save_file: str) -> None:
        if not isinstance(save_file, str):
            raise ValueError("saveFile must be a string")
        try:
            packed_DB = ((PackedDBHandle)(self.db_handle)).save("DTArchive", os.path.dirname(save_file), 
                os.path.basename(save_file), TaskMonitor.DUMMY)
            self.file = ResourceFile(save_file)
            self.update_root_category_name(self.file, self.get_root_category())
        except CancelledException:
            pass

    def save(self) -> None:
        if not isinstance(self.file.name, str):
            raise ValueError("Output File was not specified: call saveAs(String)")
        try:
            ((PackedDBHandle)(self.db_handle)).save(TaskMonitor.DUMMY)
        except CancelledException:
            pass

    @property
    def filename(self) -> str | None:
        if self.file is not None:
            return os.path.abspath(self.file.name)
        return None

    @classmethod
    def convert_filename(cls, file: str) -> str:
        fname = os.path.basename(file)
        if fname.endswith(cls.OLD_SUFFIX):
            return file
        pos = fname.rfind(cls.SUFFIX)
        if pos > 0:
            fname = fname[:pos]
        else:
            pos = fname.rfind(cls.OLD_ SUFFIX)
            if pos > 0:
                fname = fname[:pos] + cls.SUFFIX
        return os.path.join(os.path.dirname(file), fname)

    def update_root_category_name(self, new_file: ResourceFile, root: Category) -> None:
        new_name = self.get_root_name(new_file.name)
        if root.name == new_name:
            return
        try:
            root.set_name(new_name)
        except DuplicateNameException | InvalidNameException as e:
            pass

    def get_root_name(self, name: str) -> str:
        pos = os.path.basename(name).rfind(self.SUFFIX)
        if pos > 0:
            return os.path.splitext(os.path.basename(name))[0]
        else:
            return name

    def delete(self) -> None:
        self.close()
        if self.packed_DB is not None:
            self.packed_DB.dispose()
            self.packed_DB = None
        super().close()

    @property
    def closed(self) -> bool:
        return self.packed_DB is None

    def __del__(self):
        self.delete()

    @classmethod
    def delete(cls, packed_dbfile: str) -> None:
        if not isinstance(packed_dbfile, str):
            raise ValueError("packedDbFile must be a string")
        filename = os.path.abspath(packed_dbfile)
        if filename.endswith(cls.OLD_SUFFIX):
            try:
                os.remove(filename)
            except FileNotFoundError as e:
                pass
        else:
            PackedDatabase.delete(os.path.dirname(filename), os.path.basename(filename))

    @property
    def path(self) -> str | None:
        return self.file.name

    @property
    def type(self) -> ArchiveType:
        return ArchiveType.FILE

    def __str__(self):
        return f"{type(self).__name__} - {os.path.splitext(os.path.basename(self.filename))[0]}"
```

Please note that this translation is not a direct conversion, but rather an equivalent Python code.