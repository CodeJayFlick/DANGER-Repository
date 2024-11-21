Here is the translation of the Java code to Python:
```python
import os

class MultiFileLogReader:
    def __init__(self, files):
        self.files = files
        self.current_reader = None
        self.file_idx = 0

    def close(self):
        if self.current_reader is not None:
            self.current_reader.close()

    def has_next(self) -> bool:
        if self.files is None or len(self.files) == 0:
            return False
        if self.current_reader is None:
            self.current_reader = SingleFileLogReader(self.files[self.file_idx])
            self.file_idx += 1
        return self.current_reader.has_next()

    def next(self) -> object:
        if not self.has_next():
            raise NoSuchElementException()
        return self.current_reader.next()


class SingleFileLogReader:
    def __init__(self, file):
        self.file = file

    def close(self):
        pass  # TODO: implement me!

    def has_next(self) -> bool:
        try:
            with open(self.file, 'r') as f:
                return True
        except FileNotFoundError:
            return False

    def next(self) -> object:
        raise NotImplementedError("Not implemented yet!")


class NoSuchElementException(Exception):
    pass


# Example usage:
files = [os.path.join('path', 'file1.log'), os.path.join('path', 'file2.log')]
reader = MultiFileLogReader(files)
while reader.has_next():
    print(reader.next())
```
Note that I had to make some assumptions about the `SingleFileLogReader` class, as it was not fully implemented in the original Java code. Specifically:

* The `close()` method is currently a no-op, but you would need to implement this method to properly close the file.
* The `next()` method raises a `NotImplementedError`, indicating that this method has not been implemented yet.

You will likely want to modify these methods based on your specific requirements.