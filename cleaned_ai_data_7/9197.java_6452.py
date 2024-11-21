import os
from abc import ABCMeta, abstractmethod


class Database(metaclass=ABCMeta):
    def __init__(self, db_dir: str, versioned: bool = False) -> None:
        self.db_dir = db_dir
        self.versioned = versioned

    @abstractmethod
    def open(self) -> 'DBHandle':
        pass


class DBHandle(metaclass=ABCMeta):
    def __init__(self, buffer_file: str) -> None:
        self.buffer_file = buffer_file

    @abstractmethod
    def get_buffer_file(self) -> str:
        pass


def delete_dir(dir_path: str) -> bool:
    if not os.path.exists(dir_path):
        return False

    for file in os.listdir(dir_path):
        file_path = os.path.join(dir_path, file)
        if os.path.isdir(file_path):
            if not delete_dir(file_path):
                return False
        else:
            try:
                os.remove(file_path)
            except OSError as e:
                print(f"Error deleting {file_path}: {e}")
                return False

    try:
        os.rmdir(dir_path)
    except OSError as e:
        print(f"Error removing directory: {e}")

    return True


class DatabaseManager(metaclass=ABCMeta):
    def __init__(self, db_dir: str) -> None:
        self.db_dir = db_dir

    @abstractmethod
    def refresh(self) -> None:
        pass


def get_file_versions(file_list: list) -> list[int]:
    versions = []
    for file in file_list:
        start_idx = file.find('.')
        end_idx = file.find('.', start_idx + 1)
        if start_idx < 0 or end_idx < start_idx:
            print(f"Bad file name: {file}")
            continue

        version_str = file[start_idx + 1:end_idx]
        try:
            versions.append(int(version_str))
        except ValueError as e:
            print(f"Bad file name: {file}")

    return sorted(versions)


class DBBufferFileManager(metaclass=ABCMeta):
    def __init__(self, db_dir: str) -> None:
        self.db_dir = db_dir

    @abstractmethod
    def get_buffer_file(self, version: int) -> str:
        pass


def main():
    # Example usage:

    db_dir = '/path/to/db'
    database_manager = DatabaseManager(db_dir)

    try:
        database_manager.refresh()
    except FileNotFoundError as e:
        print(f"Error refreshing database: {e}")


if __name__ == "__main__":
    main()

