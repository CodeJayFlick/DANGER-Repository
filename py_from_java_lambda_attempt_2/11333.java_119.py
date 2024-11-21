Here is a translation of the provided Java code into equivalent Python:

```Python
class TestDummyDomainFolder:
    def __init__(self, parent=None, name=''):
        self.parent = parent
        self.folder_name = name
        self.sub_folders = []
        self.files = []

    def remove(self, file):
        if isinstance(file, TestDummyDomainFile):
            self.files.remove(file)

    def compare_to(self, other):
        raise NotImplementedError

    @property
    def name(self):
        return self.folder_name

    def set_name(self, new_name):
        raise NotImplementedError

    def get_project_locator(self):
        raise NotImplementedError

    def get_project_data(self):
        raise NotImplementedError

    def pathname(self):
        if self.parent:
            parent_pathname = f"{self.parent.pathname()}/" if self.parent else ""
            return parent_pathname + self.folder_name
        return "/"

    def is_in_writable_project(self):
        raise NotImplementedError

    @property
    def parent(self):
        return self.parent

    def get_folders(self):
        return list(self.sub_folders)

    def get_folder(self, name):
        for folder in self.sub_folders:
            if folder.name == name:
                return folder
        return None

    def get_file(self, name):
        for file in self.files:
            if file.name == name:
                return file
        return None

    @property
    def is_empty(self):
        return not (self.files or self.sub_folders)

    def get_files(self):
        return list(self.files)

    def create_file(self, name, obj=None, monitor=None):
        if isinstance(obj, TestDummyDomainFile):
            raise NotImplementedError
        file = TestDummyDomainFile(self, name)
        self.files.append(file)
        return file

    def delete(self):
        if not self.is_empty:
            raise FolderNotEmptyException("")

class TestDummyDomainFile:
    pass

class DomainFolder:
    pass

class DomainFile:
    pass

class ProjectLocator:
    pass

class ProjectData:
    pass
```

Please note that the Python code does not exactly replicate the Java code. It is a translation of the provided Java code into equivalent Python, but it may not be identical due to differences in syntax and semantics between the two languages.