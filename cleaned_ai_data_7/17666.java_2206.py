import logging
from pathlib import Path
from typing import List

class WalChecker:
    def __init__(self, wal_folder: str):
        self.wal_folder = wal_folder
        self.logger = logging.getLogger(__name__)
        self.logger.info("Initializing WalChecker with folder {}".format(wal_folder))

    def do_check(self) -> List[Path]:
        try:
            wal_folder_path = Path(self.wal_folder)
            if not wal_folder_path.exists() or not wal_folder_path.is_dir():
                raise SystemCheckException(f"Folder {wal_folder} does not exist")

            storage_wal_folders = [f for f in wal_folder_path.iterdir() if f.is_dir()]
            if len(storage_wal_folders) == 0:
                self.logger.info("No sub-directories under the given directory, check ends")
                return []

            failed_files = []
            for dir_index, folder in enumerate(storage_wal_folders):
                storage_wal_folder_path = Path(folder)
                self.logger.info(f"Checking the No.{dir_index} directory {storage_wal_folder_path.name}")
                wal_file_path = storage_wal_folder_path / "wal"
                if not check_file(wal_file_path):
                    failed_files.append(wal_file_path)

            return failed_files

        except SystemCheckException as e:
            self.logger.error(f"System Check Exception: {e}")

    def report(self, failed_files: List[Path]):
        if len(failed_files) == 0:
            self.logger.info("Check finished. There is no damaged file")
        else:
            self.logger.error(f"There are {len(failed_files)} failed files. They are {failed_files}")


class SystemCheckException(Exception):
    pass


def check_file(file_path: Path) -> bool:
    if not file_path.exists():
        self.logger.debug("No wal file in this dir, skipping")
        return True

    if file_path.stat().st_size > 0 and file_path.stat().st_size < SingleFileLogReader.LEAST_LOG_SIZE:
        # contains only one damaged log
        self.logger.error(f"{file_path} fails the check because it is non-empty but does not contain enough bytes even for one log.")
        return False

    try:
        with open(file_path, 'rb') as f:
            while True:
                f.seek(0)
                if not SingleFileLogReader(f).has_next():
                    break
                if SingleFileLogReader(f).is_file_corrupted():
                    self.logger.error(f"{file_path} fails the check because")
                    return False

    except IOError as e:
        self.logger.error(f"{file_path} fails the check because {e}")
        return False


def main(args: List[str]) -> None:
    if len(args) < 1:
        logging.error("No enough args: require the walRootDirectory")
        return

    checker = WalChecker(args[0])
    files = checker.do_check()
    checker.report(files)


if __name__ == "__main__":
    main(sys.argv[1:])
