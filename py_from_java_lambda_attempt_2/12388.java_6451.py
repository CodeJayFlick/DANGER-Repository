Here is the translation of the Java interface `SourceArchive` into a Python class:

```Python
class SourceArchive:
    def __init__(self):
        self._source_archive_id = None
        self._domain_file_id = None
        self._archive_type = None
        self._name = None
        self._last_sync_time = 0
        self._dirty = False

    @property
    def source_archive_id(self):
        return self._source_archive_id

    @source_archive_id.setter
    def set_source_archive_id(self, value):
        self._source_archive_id = value

    @property
    def domain_file_id(self):
        return self._domain_file_id

    @domain_file_id.setter
    def set_domain_file_id(self, value):
        self._domain_file_id = value

    @property
    def archive_type(self):
        return self._archive_type

    @archive_type.setter
    def set_archive_type(self, value):
        self._archive_type = value

    @property
    def name(self):
        return self._name

    @name.setter
    def set_name(self, value):
        self._name = value

    @property
    def last_sync_time(self):
        return self._last_sync_time

    @last_sync_time.setter
    def set_last_sync_time(self, value):
        self._last_sync_time = value

    @property
    def is_dirty(self):
        return self._dirty

    @is_dirty.setter
    def set_is_dirty(self, value):
        self._dirty = value


# Example usage:
source_archive = SourceArchive()
source_archive.set_source_archive_id("12345")
source_archive.set_domain_file_id("domain_file_1")
source_archive.set_archive_type("PROGRAM")
source_archive.set_name("Source Archive 1")
source_archive.set_last_sync_time(1643723400)
print(source_archive.source_archive_id)  # prints: 12345
```

Note that Python does not have direct equivalent of Java's `interface` keyword. Instead, we define a class with methods and properties to achieve similar functionality.