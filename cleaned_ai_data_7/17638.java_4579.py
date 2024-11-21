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
