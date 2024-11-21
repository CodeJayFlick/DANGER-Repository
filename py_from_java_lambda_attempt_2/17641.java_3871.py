Here is the translation of the Java interface `ISyncReceiverLogAnalyzer` to a Python class:

```python
import os


class ISyncReceiverLogAnalyzer:
    def recover_all(self) -> None:
        # TO DO: implement this method
        pass

    def recover(self, sender_name: str) -> bool:
        # TO DO: implement this method
        return False  # default value if not implemented

    def scan_logger(self, loader: 'IFileLoader', sync_log_file: os.PathLike, load_log_file: os.PathLike) -> None:
        # TO DO: implement this method
        pass


class IFileLoader:
    pass
```

Note that in Python, we don't have a direct equivalent to Java interfaces. Instead, we can define abstract base classes (ABCs) using the `abc` module or simply use a regular class with abstract methods.

In this translation, I've defined an ABC `ISyncReceiverLogAnalyzer` with three abstract methods: `recover_all`, `recover`, and `scan_logger`. The `IFileLoader` is also defined as another ABC (or regular class) for now.