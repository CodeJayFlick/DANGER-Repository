Here is the translation of the Java interface `ILoadLogger` to a Python class:

```python
class ILoadLogger:
    LOAD_DELETED_FILE_NAME_START = "load deleted files start"
    LOAD_TSFILE_START = "load tsfile start"

    def __init__(self):
        pass  # No equivalent in Python, but included for consistency

    def start_load_deleted_files(self) -> None:
        raise NotImplementedError("Must be implemented by subclass")

    def finish_load_deleted_file(self, file: str) -> None:
        raise NotImplementedError("Must be implemented by subclass")

    def start_load_tsfiles(self) -> None:
        raise NotImplementedError("Must be implemented by subclass")

    def finish_load_tsfile(self, file: str) -> None:
        raise NotImplementedError("Must be implemented by subclass")

    def close(self) -> None:
        raise NotImplementedError("Must be implemented by subclass")
```

Note that I've used Python's `raise` statement to indicate that these methods must be implemented by a subclass. This is equivalent to the Java interface's requirement for implementing classes.

Also, since there are no specific exceptions thrown in the original code (only an `IOException`), I didn't include any exception handling in this translation.