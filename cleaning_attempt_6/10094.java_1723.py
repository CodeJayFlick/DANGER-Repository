import os
from abc import ABCMeta, abstractmethod


class VersionedDatabase:
    def __init__(self, db_dir: str, ver_db_listener):
        self.db_dir = db_dir
        self.ver_db_listener = ver_db_listener

    @property
    def current_version(self) -> int:
        return 0

    @current_version.setter
    def current_version(self, value: int):
        self._current_version = value

    @property
    def min_version(self) -> int:
        return -1

    @min_version.setter
    def min_version(self, value: int):
        self._min_version = value

    def create_versioned_database(self, db_dir: str, buffer_size: int,
                                   ver_db_listener: 'VersionedDBListener', checkout_id: long) -> 'LocalManagedBufferFile':
        return LocalManagedBufferFile(db_dir, buffer_size, self.bf_mgr, checkout_id)

    def get_minimum_version(self):
        with self.sync_object:
            return self.min_version

    def delete_minimum_version(self):
        with self.sync_object:
            if self.min_version == self.current_version:
                raise IOException("Unable to delete last remaining version")
            # Rename previous version/file
            file = self.bf_mgr.get_file(self.min_version)
            change_file = self.bf_mgr.get_change_data_file(self.min_version)
            del_file = os.path.join(os.path.dirname(file), f"{os.path.basename(file)}.delete")
            del_change_file = os.path.join(os.path.dirname(change_file),
                                            f"{os.path.basename(change_file)}.delete")

            if not file.rename(del_file):
                raise FileInUseException(f"Version {self.min_version} is in use")
            else:
                change_file.rename(del_change_file)
                self.bf_mgr.get_buffer_file(self.current_version).rename(file)

    def delete_current_version(self):
        with self.sync_object:
            if self.min_version == self.current_version:
                raise IOException("Unable to delete last remaining version")

            # Re-build buffer file for (currentVersion-1)
            prev_ver = self.current_version - 1
            file = self.bf_mgr.get_buffer_file(prev_ver)

            if not file.exists():
                src_bf = open_buffer_file_for_update(self.current_version, -1)
                try:
                    src_bf.clone(file, None)
                except CancelledException as e:
                    raise AssertException() from e

                finally:
                    src_bf.close()

            # Rename previous version/file
            file = self.bf_mgr.get_file(prev_ver)
            change_file = self.bf_mgr.get_change_data_file(prev_ver)

            del_file = os.path.join(os.path.dirname(file), f"{os.path.basename(file)}.delete")
            del_change_file = os.path.join(os.path.dirname(change_file),
                                            f"{os.path.basename(change_file)}.delete")

            if not file.rename(del_file):
                raise FileInUseException(f"Version {prev_ver} is in use")

            else:
                change_file.rename(del_change_file)
                self.bf_mgr.get_buffer_file(self.current_version).rename(file)

    def open_buffer_file_for_update(self, checkout_id: long) -> 'LocalManagedBufferFile':
        if not self.update_allowed:
            raise IOException("Update use not permitted")
        with self.sync_object:
            min_change_data_ver = self.ver_db_listener.get_checkout_version(checkout_id)
            return LocalManagedBufferFile(self.bf_mgr, True, min_change_data_ver, checkout_id)

    def db_moved(self, new_dir: str) -> None:
        with self.sync_object:
            self.db_dir = new_dir
            self.refresh()

    def scan_files(self, repair: bool):
        with self.sync_object:
            super().scan_files(repair)
            if self.current_version != 0 and repair:
                self.ver_db_listener.versions_changed(self.min_version, self.current_version)

    @abstractmethod
    class VerDBBufferFileManager(BufferFileManager):

        def get_current_version(self) -> int:
            return self.current_version

        def get_buffer_file(self, version: int):
            return os.path.join(self.db_dir,
                                 f"{DATABASE_FILE_PREFIX}{version}{BUFFER_FILE_EXTENSION}")

        def get_version_file(self, version: int):
            return os.path.join(self.db_dir,
                                 f"{VERSION_FILE_PREFIX}{version}{BUFFER_FILE_EXTENSION}")

        def get_change_data_file(self, version: int):
            return os.path.join(self.db_dir,
                                 f"{CHANGE_FILE_PREFIX}{version}{BUFFER_FILE_EXTENSION}")

    @abstractmethod
    class LocalManagedBufferFile:
        pass

class DBHandle:
    pass

class IOException(Exception):
    pass

class FileInUseException(IOException):
    pass

class CancelledException(Exception):
    pass

class AssertException(Exception):
    pass


# Usage example:

ver_db_listener = VersionedDBListener()
db_dir = "path/to/db"
bf_mgr = VerDBBufferFileManager()

versioned_database = VersionedDatabase(db_dir, ver_db_listener)
buffer_file = versioned_database.create_versioned_database(db_dir, 1024, ver_db_listener, -1)

# Use the buffer file
try:
    with open(buffer_file, 'rb') as f:
        # Read from or write to the buffer file
        pass

except CancelledException as e:
    raise AssertException() from e

finally:
    try:
        if not buffer_file.exists():
            versioned_database.delete_minimum_version()
    except IOException as e:
        print(f"Error: {e}")

try:
    with open(buffer_file, 'rb') as f:
        # Read from or write to the buffer file
        pass

except CancelledException as e:
    raise AssertException() from e

finally:
    try:
        if not buffer_file.exists():
            versioned_database.delete_current_version()
    except IOException as e:
        print(f"Error: {e}")
