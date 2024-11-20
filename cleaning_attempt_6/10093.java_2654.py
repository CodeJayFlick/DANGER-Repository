import os
from io import BufferedReader, BufferedWriter

class PrivateDatabase:
    def __init__(self, db_dir: str, db_file_listener=None) -> None:
        self.db_dir = db_dir
        if db_file_listener is not None:
            super().__init__(db_dir, db_file_listener)

    @classmethod
    def create_database(cls, db_dir: str, db_file_listener=None, buffer_size: int = 0) -> 'LocalManagedBufferFile':
        return cls(db_dir, db_file_listener).create_buffer_file(buffer_size)

    def set_is_checkout_copy(self, state: bool) -> None:
        self.is_check_out_copy = state

    def open_buffer_file(self) -> 'LocalManagedBufferFile':
        with self.sync_object:
            return LocalManagedBufferFile(self.bf_mgr, False, -1, -1)

    def open_buffer_file_for_update(self) -> 'LocalManagedBufferFile':
        if not self.update_allowed:
            raise IOException("Update use not permitted")
        with self.sync_object:
            return LocalManagedBufferFile(self.bf_mgr, True, -1, -1)

    @property
    def can_recover(self) -> bool:
        return BufferMgr.can_recover(self.bf_mgr)

    def db_moved(self, dir: str) -> None:
        with self.sync_object:
            self.db_dir = dir
            self.refresh()

    def update_checkout_copy(self, src_file: 'ManagedBufferFile', old_version: int, monitor=None) -> None:
        if not self.is_check_out_copy:
            raise IOException("Database is not a checkout copy")
        with self.sync_object:
            if src_file is not None:
                local_bf = LocalManagedBufferFile(self.bf_mgr, True, -1, -1)
                try:
                    local_bf.update_from(src_file, old_version, monitor)  # performs a save
                    local_bf.close()
                finally:
                    if not local_bf.success:
                        local_bf.delete()

            (os.path.join(self.db_dir, CUMULATIVE_CHANGE_FILENAME)).delete()
            (os.path.join(self.db_dir, CUMULATIVE_MODMAP_FILENAME)).delete()

    def update_checkout_copy(self) -> None:
        if not self.is_check_out_copy:
            raise IOException("Database is not a checkout copy")
        with self.sync_object:
            (os.path.join(self.db_dir, CUMULATIVE_CHANGE_FILENAME)).delete()
            (os.path.join(self.db_dir, CUMULATIVE_MODMAP_FILENAME)).delete()

    def update_checkout_from(self, other_db: 'PrivateDatabase') -> None:
        if not self.is_check_out_copy:
            raise IOException("Database is not a checkout copy")
        with self.sync_object:
            new_version = self.current_version + 1
            other_buf_file = other_db.bf_mgr.get_buffer_file(other_db.current_version)
            other_change_file = os.path.join(other_db.db_dir, CUMULATIVE_CHANGE_FILENAME)
            other_map_file = os.path.join(other_db.db_dir, CUMULATIVE_MODMAP_FILENAME)
            new_buf_file = self.bf_mgr.get_buffer_file(new_version)
            change_file = os.path.join(self.db_dir, CUMULATIVE_CHANGE_FILENAME)
            map_file = os.path.join(self.db_dir, CUMULATIVE_MODMAP_FILENAME)
            backup_change_file = os.path.join(self.db_dir, CUMULATIVE_CHANGE_FILENAME + ".bak")
            backup_map_file = os.path.join(self.db_dir, CUMULATIVE_MODMAP_FILENAME + ".bak")

            if not other_buf_file.exists():
                raise IOException("Update file not found")

            try:
                if map_file.exists() and not os.rename(map_file, backup_map_file):
                    raise IOException("Concurrent database modification error (2)")
                if change_file.exists() and not os.rename(change_file, backup_change_file):
                    raise IOException("Concurrent database modification error (3)")

                other_map_file.rename(backup_map_file)
                other_change_file.rename(backup_change_file)

            except Exception as e:
                new_buf_file.delete()
                map_file = os.path.join(self.db_dir, CUMULATIVE_MODMAP_FILENAME + ".bak")
                change_file = os.path.join(self.db_dir, CUMULATIVE_CHANGE_FILENAME + ".bak")

        self.current_version = new_version
        self.last_modified = new_buf_file.stat().st_mtime

    def output(self, file: str, name: str, filetype: int, content_type: str, monitor=None) -> None:
        with self.sync_object:
            file_path = os.path.join(file)
            item_in = BufferedReader(open(os.path.join(self.db_dir, "file"), 'rb'))
            try:
                ItemSerializer.output_item(name, content_type, filetype, item_in.read(), file_path, monitor)
            finally:
                item_in.close()
