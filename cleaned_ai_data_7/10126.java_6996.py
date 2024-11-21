class RemoteDatabaseItem:
    def __init__(self, repository: 'RepositoryAdapter', item: 'RepositoryItem'):
        super().__init__(repository, item)

    @property
    def length(self) -> int:
        return self.repository.get_length(self.parent_path, self.item_name)

    @property
    def item_type(self) -> str:
        return RepositoryItem.DATABASE

    @property
    def can_recover(self) -> bool:
        return False

    def open_versioned_file(self, version: int, min_change_data_ver: int = -1) -> 'ManagedBufferFileAdapter':
        return self.repository.open_database(self.parent_path, self.item_name, version, min_change_data_ver)

    def open_latest_version_file(self) -> 'ManagedBufferFileAdapter':
        return self.repository.open_database(self.parent_path, self.item_name, RepositoryItem.LATEST_VERSION, -1)

    def open_for_update(self, checkout_id: int) -> 'ManagedBufferFileAdapter':
        return self.repository.open_database(self.parent_path, self.item_name, checkout_id)

    def update_checkout_version(self, checkout_id: int, checkout_version: int, user: str = '') -> None:
        self.repository.update_checkout_version(self.parent_path, self.item_name, checkout_id, checkout_version)

    @property
    def has_checkouts(self) -> bool:
        return self.repository.has_checkouts(self.parent_path, self.item_name)

    @property
    def is_checkin_active(self) -> bool:
        return self.repository.is_checkin_active(self.parent_path, self.item_name)

    def output_file(self, file: 'File', version: int = RepositoryItem.LATEST_VERSION, monitor=None):
        bf = self.open_versioned_file(version)
        try:
            tmp_file = tempfile.NamedTemporaryFile(suffix='.tmp')
            tmp_bf = LocalBufferFile(tmp_file.name, bf.get_buffer_size())
            try:
                LocalBufferFile.copy_file(bf, tmp_bf, None, monitor)
                tmp_bf.close()
                
                item_in = open(tmp_file.name, 'rb')
                try:
                    ItemSerializer.output_item(self.item_name, self.content_type, DatabaseItem.DATABASE_FILE_TYPE,
                                                 os.path.getsize(file), item_in, file, monitor)
                finally:
                    if not hasattr(item_in, 'close'):
                        pass
                    else:
                        item_in.close()
            finally:
                tmp_bf.close()
                tmp_file.close()
        finally:
            bf.close()

class RepositoryAdapter:
    def get_length(self, parent_path: str, item_name: str) -> int:
        # implement this method

    def open_database(self, parent_path: str, item_name: str, version: int = -1, min_change_data_ver=-1) -> 'ManagedBufferFileAdapter':
        # implement this method

class RepositoryItem:
    DATABASE = ''
    LATEST_VERSION = 0
