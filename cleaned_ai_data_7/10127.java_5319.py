class RemoteFileSystem:
    def __init__(self, repository):
        self.repository = repository
        self.event_manager = FileSystemEventManager(True)
        self.repository.set_file_system_listener(self.event_manager)

    def get_user_name(self):
        try:
            return self.repository.get_user().get_name()
        except Exception as e:
            return None

    def add_file_system_listener(self, listener):
        self.event_manager.add(listener)

    def remove_file_system_listener(self, listener):
        self.event_manager.remove(listener)

    def is_versioned(self):
        return True

    def is_online(self):
        return self.repository.is_connected()

    def is_read_only(self):
        try:
            return self.repository.get_user().is_read_only()
        except Exception as e:
            return False

    def is_shared(self):
        return True

    def get_item_count(self):
        try:
            return self.repository.get_item_count()
        except Exception as e:
            return 0

    def get_item_names(self, folder_path):
        items = self.repository.get_items(folder_path)
        names = [item.name for item in items]
        return names

    def get_item(self, folder_path, name):
        item = self.repository.get_item(folder_path, name)
        if item is None:
            return None
        elif item.item_type == RepositoryItem.DATABASE:
            return RemoteDatabaseItem(self.repository, item)
        else:
            raise Exception("Unsupported file type")

    def get_folder_names(self, parent_path):
        return self.repository.get_subfolder_list(parent_path)

    def create_file(self, parent_path, name, packed_file, monitor=None, user=None):
        raise Exception("Versioned filesystem does not support createFile")

    def delete_folder(self, folder_path):
        raise Exception("Versioned filesystem does not support deleteFolder")

    def move_folder(self, parent_path, folder_name, new_parent_path):
        self.repository.move_folder(parent_path, new_parent_path, folder_name, folder_name)

    def rename_folder(self, parent_path, folder_name, new_folder_name):
        self.repository.move_folder(parent_path, parent_path, folder_name, new_folder_name)

    def move_item(self, parent_path, name, new_parent_path, new_name):
        self.repository.move_item(parent_path, new_parent_path, name, new_name)

    def folder_exists(self, folder_path):
        return self.repository.folder_exists(folder_path)

    def file_exists(self, folder_path, item_name):
        return self.repository.file_exists(folder_path, item_name)

    def connection_state_changed(self, adapter):
        if adapter == self.repository:
            self.event_manager.synchronize()

    def dispose(self):
        self.event_manager.dispose()
