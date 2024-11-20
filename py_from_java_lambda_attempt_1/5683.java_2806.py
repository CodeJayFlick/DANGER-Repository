Here is the translation of the given Java code into Python:

```Python
class FileSystemRef:
    def __init__(self, fs):
        self.fs = fs
        self.ref_closed = False

    @property
    def filesystem(self):
        return self.fs

    def dup(self):
        return type(self)(self.fs)

    def close(self):
        if not self.is_ref_closed():
            self.fs.get_ref_manager().release(self)
            self.ref_closed = True

    def is_ref_closed(self):
        return self.ref_closed

    def __del__(self):
        if not self.is_ref_closed():
            print(f"Unclosed FilesytemRef: {self.fs}")
```

Note that Python does not have a direct equivalent to Java's `finalize()` method. The closest thing in Python is the `__del__` method, which gets called when an object is garbage collected. However, this can be unreliable and should generally be avoided if possible.

Also note that I've used Python's property decorator (`@property`) to create a getter for the `filesystem` attribute. This allows you to access the underlying `fs` attribute as if it were a regular method or property.