Here is the translation of the given Java code into equivalent Python:

```Python
class RootGhidraFolderData:
    def __init__(self, file_manager, listener):
        super().__init__(file_manager, listener)

    def get_domain_folder(self):
        return RootGhidraFolder(self.get_project_file_manager(), self.get_change_listener())

    @property
    def versioned_file_system(self):
        pass

    def set_versioned_file_system(self, fs):
        self._versioned_file_system = fs

    @property
    def private_exists(self):
        return True

    @private_exists.setter
    def private_exists(self, value):
        pass  # This is equivalent to the Java method with no implementation.

    @property
    def shared_exists(self):
        return True


class RootGhidraFolder:
    def __init__(self, file_manager, listener):
        self.file_manager = file_manager
        self.listener = listener

```

Note that Python does not have direct equivalent of Java's `@Override` annotation. The `super().__init__()` call is used to invoke the parent class constructor in Python.

Also note that I've made some assumptions about how you might want your code structured, and this may need adjusting based on your specific needs.