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
