Here is the translation of the Java interface `GFile` into a Python class:

```Python
class GFile:
    def __init__(self):
        pass

    @property
    def filesystem(self):
        # Implement this method in your subclass to return the owning filesystem.
        raise NotImplementedError("filesystem not implemented")

    @property
    def fsrl(self):
        # Implement this method in your subclass to return the FSRL of this file.
        raise NotImplementedError("fsrl not implemented")

    @property
    def parent_file(self):
        # Implement this method in your subclass to return the parent directory of this file.
        raise NotImplementedError("parent_file not implemented")

    @property
    def path(self):
        # Implement this method in your subclass to return the path and filename of this file, relative to its owning filesystem.
        raise NotImplementedError("path not implemented")

    @property
    def name(self):
        # Implement this method in your subclass to return the name of this file.
        raise NotImplementedError("name not implemented")

    def is_directory(self):
        # Implement this method in your subclass to check if this file is a directory. Default returns False.
        return False

    def get_length(self):
        # Implement this method in your subclass to return the length of this file, or -1 if not known. Default returns -1.
        return -1

    @property
    def last_modified(self):
        # Implement this method in your subclass to return the last modified time of this file. Default returns -1.
        return -1

    def get_listing(self):
        # This is a default implementation that calls the filesystem's listing method with this GFile as an argument.
        raise NotImplementedError("get_listing not implemented")
```

This Python class does not have direct equivalent to Java interface methods like `getFilesystem()`, because in Python, you can't define abstract methods directly. Instead, we use properties and a default implementation for each method that requires the subclass to implement it.

The `@property` decorator is used to make the attributes of this class read-only. The actual values are returned by the getter functions (`filesystem`, `fsrl`, etc.).