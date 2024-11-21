Here is the translation of the given Java code into Python:

```Python
class ProgramArchive:
    def __init__(self, program):
        self.program = program
        self.data_type_manager = program.get_data_type_manager()

    @property
    def get_program(self):
        return self.program

    @property
    def get_data_type_manager(self):
        return self.data_type_manager

    def get_name(self):
        return self.data_type_manager.name

    def compare_to(self, archive):
        if isinstance(archive, BuiltInArchive):
            return 1
        else:
            return -1  # Programs are always before everything except for built-ins

    @property
    def is_modifiable(self):
        return True

    def close(self):
        pass  # Can't directly close the program archive. Instead you must close the Program.

    @property
    def is_changed(self):
        return False

    @property
    def is_savable(self):
        return False

    def save(self, *args):
        raise Exception("Can't 'Save' so do nothing.")

    def save_as(self, component):
        pass  # Can't "Save As" so do nothing.

    def get_domain_file(self):
        return self.program.get_domain_file()

    def get_domain_object(self):
        return self.program

    @property
    def icon(self, expanded=False):
        if expanded:
            return 'open_book_red.png'
        else:
            return 'closed_book_red.png'

class BuiltInArchive:
    pass  # This class is not defined in the given Java code.
```

Please note that this translation does not include all classes and methods from the original Java code.