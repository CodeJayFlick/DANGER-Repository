Here is the equivalent Python code:

```Python
class DuplicateIdException(Exception):
    def __init__(self, new_archive_name: str, existing_archive_name: str) -> None:
        super().__init__(
            f"Attempted to open a datatype archive with the same ID as datatype "
            f"archive that is already open. {new_archive_name} has the same id as "
            f"{existing_archive_name}\nOne is probably a copy of the other.  Ghidra does not support using "
            f"archive copies within the same project!"
        )
        self.new_archive_name = new_archive_name
        self.existing_archive_name = existing_archive_name

    def get_new_archive_name(self) -> str:
        return self.new_archive_name

    def get_existing_archive_name(self) -> str:
        return self.existing_archive_name
```

Note that Python does not have a direct equivalent to Java's `package` declaration, so I omitted it. Also, the exception handling mechanism is slightly different between Java and Python - in Python, we can simply inherit from the built-in `Exception` class and override its constructor (`__init__`) method.