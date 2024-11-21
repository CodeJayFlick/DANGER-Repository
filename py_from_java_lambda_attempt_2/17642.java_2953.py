Here is the translation of the Java interface `ISyncReceiverLogger` to a Python class:

```python
class ISyncReceiverLogger:
    SYNC_DELETED_FILE_NAME_START = "sync deleted file names start"
    SYNC_TSFILE_START = "sync tsfile start"

    def start_sync_deleted_files_name(self) -> None:
        pass

    def finish_sync_deleted_file_name(self, file: str) -> None:
        pass

    def start_sync_tsfiles(self) -> None:
        pass

    def finish_sync_tsfile(self, file: str) -> None:
        pass

    def close(self) -> None:
        pass
```

Note that in Python:

* The `package` declaration is not necessary.
* The `import java.io.File;` and `import java.io.IOException;` statements are also not needed, as the equivalent modules (`os`, `io`) are built-in to Python.
* The interface methods (e.g. `startSyncDeletedFilesName()`) become method definitions in Python, with no return type specified by default.
* The Java-style docstrings have been removed, as they are not necessary or common in Python.

This is a direct translation of the original code; it does not include any actual implementation for these methods, only their signatures.