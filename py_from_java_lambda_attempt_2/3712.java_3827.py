Here is the translation of the given Java code into equivalent Python:

```Python
class InvalidFileArchive:
    def __init__(self, archive_manager, source_archive):
        self.archive_manager = archive_manager
        self.universal_id = source_archive.source_archive_id
        self.archive_type = source_archive.archive_type
        self.name = source_archive.name
        self.domain_file_id = source_archive.domain_file_id

    def get_data_type_manager(self):
        return None

    def is_modifiable(self):
        return False

    def get_name(self):
        return self.name

    def compare_to(self, archive):
        if isinstance(archive, InvalidFileArchive):
            return self.get_name().lower() == archive.get_name().lower()
        else:
            return 1

    @property
    def archive_type(self):
        return self.archive_type

    @property
    def domain_file_id(self):
        return self.domain_file_id

    def close(self):
        self.archive_manager.archive_closed(self)

    def is_changed(self):
        return False

    def is_savable(self):
        return False

    def save(self, *args):
        pass  # Can't "Save" so do nothing.

    def save_as(self, component):
        pass  # Can't "Save As" so do nothing.

    @property
    def universal_id(self):
        return self.universal_id

    def get_icon(self, expanded=False):
        return None  # Equivalent to the ImageIcon in Java.
```

Please note that Python does not have direct equivalent of `ImageIcon` class. It has a built-in module called `tkinter` which can be used for creating GUI applications and displaying images. However, it is complex task and requires knowledge of both Python and Tkinter.

Also, please note that the translation from Java to Python may require some adjustments based on specific requirements or constraints.