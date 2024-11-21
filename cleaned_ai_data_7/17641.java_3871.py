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
