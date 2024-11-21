Here is the translation of the Java code to Python:
```
class GFileLocal:
    def __init__(self, f, path, fsrl, fs, parent=None):
        self.fs = fs
        self.fsrl = fsrl
        self.path = path
        self.f = f
        self.parent = parent

    @property
    def filesystem(self):
        return self.fs

    @property
    def fsrl(self):
        return self.fsrl

    @property
    def parent_file(self):
        return self.parent

    @property
    def path(self):
        return self.path

    @property
    def name(self):
        return self.fsrl.name

    def is_directory(self):
        return self.f.is_dir()

    def get_length(self):
        return self.f.size

    def get_last_modified(self):
        return self.f.mtime

    def get_local_file(self):
        return self.f

    def __str__(self):
        return f"Local {self.f} with path {self.path}"
```
Note that I used the `@property` decorator to create read-only properties for the attributes, which is a common pattern in Python. I also replaced the Java-style constructor with an initializer method (`__init__`) and removed the explicit type declarations (e.g., `GFileLocal implements GFile`).