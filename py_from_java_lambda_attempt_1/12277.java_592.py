Here is the translation of the given Java code into Python:

```Python
class DataTypeImpl:
    def __init__(self, path: str, name: str, universal_id=None, source_archive=None, last_change_time=0, data_manager=None):
        self.path = path
        self.name = name
        self.universal_id = universal_id if universal_id else "Unknown"
        self.source_archive = source_archive
        self.last_change_time = last_change_time

    def get_value_class(self) -> type:
        return None

    @property
    def default_settings(self):
        return {}

    @default_settings.setter
    def default_settings(self, settings: dict):
        self._default_settings = settings

    @property
    def settings_definitions(self):
        return []

    def check_valid_name(self, name: str) -> None:
        if not DataUtilities.is_valid_data_type_name(name):
            raise InvalidNameException("Invalid Name: " + name)

    @default_settings.setter
    def default_settings(self, settings: dict):
        self._default_settings = settings

    @property
    def path_name(self) -> str:
        return self.path

    @property
    def alignment(self) -> int:
        length = self.length()
        if length < 0:
            return 1
        else:
            return self.data_organization.alignment()

    def add_parent(self, dt: 'DataType') -> None:
        self.parent_list.append(dt)

    def remove_parent(self, dt: 'DataType') -> None:
        for ref in self.parent_list[:]:
            if ref.get() == dt:
                self.parent_list.remove(ref)
                break

    @property
    def parents(self) -> list:
        return [ref.get() for ref in self.parent_list]

    def notify_size_changed(self):
        self.notify_parents(lambda x: x.data_type_size_changed(self))

    def notify_alignment_changed(self):
        self.notify_parents(lambda x: x.data_type_alignment_changed(self))

    def notify_name_changed(self, old_name: str) -> None:
        self.notify_parents(lambda x: x.data_type_name_changed(self, old_name))

    def notify_deleted(self) -> None:
        self.notify_parents(lambda x: x.data_type_deleted(self))

    def notify_replaced(self, replacement: 'DataType') -> None:
        self.notify_parents(lambda x: x.data_type_replaced(self, replacement))

    @property
    def last_change_time(self):
        return self._last_change_time

    @last_change_time.setter
    def last_change_time(self, time: int) -> None:
        self._last_change_time = time

    @property
    def source_archive(self) -> 'SourceArchive':
        return self._source_archive

    @source_archive.setter
    def source_archive(self, archive: 'SourceArchive') -> None:
        self._source_archive = archive

    @property
    def universal_id(self):
        return self._universal_id

    @universal_id.setter
    def universal_id(self, id: str) -> None:
        self._universal_id = id

class SourceArchive:
    pass

class UniversalID:
    pass

def notify_parents(consumer: callable) -> None:
    for ref in parent_list[:]:
        if ref.get() is not None:
            consumer(ref.get())

if __name__ == "__main__":
    # Example usage
    dt = DataTypeImpl("path", "name")
    print(dt.path_name)
```

Please note that this translation does not include the entire code, only the provided Java class. Also, Python doesn't support exact equivalent of Java's abstract classes and interfaces.