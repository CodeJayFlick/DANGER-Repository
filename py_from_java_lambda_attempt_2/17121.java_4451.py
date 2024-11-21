Here's the equivalent Python code:

```Python
class SystemCheckException(Exception):
    def __init__(self, wal_folder: str) -> None:
        message = f"[{wal_folder}] is not a directory"
        super().__init__(message)
```

Note that in Python, we don't need to specify types for variables or function parameters. Also, the equivalent of Java's `extends` keyword (in this case, extending from `IoTDBException`) would be simply inheriting from the parent class (`Exception`).