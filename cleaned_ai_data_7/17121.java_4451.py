class SystemCheckException(Exception):
    def __init__(self, wal_folder: str) -> None:
        message = f"[{wal_folder}] is not a directory"
        super().__init__(message)
