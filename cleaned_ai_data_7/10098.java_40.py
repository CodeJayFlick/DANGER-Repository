class FileSystem:
    SEPARATOR = '/'

    def __init__(self):
        pass

    def get_user_name(self) -> str:
        raise NotImplementedError("Method not implemented")

    def is_versioned(self) -> bool:
        raise NotImplementedError("Method not implemented")

    def is_online(self) -> bool:
        raise NotImplementedError("Method not implemented")

    def is_read_only(self) -> bool:
        raise NotImplementedError("Method not implemented")

    def get_item_count(self) -> int:
        raise NotImplementedError("Method not implemented")

    def get_item_names(self, folder_path: str) -> list[str]:
        raise NotImplementedError("Method not implemented")

    def get_item(self, folder_path: str, name: str) -> 'FolderItem':
        raise NotImplementedError("Method not implemented")

    def get_folder_names(self, folder_path: str) -> list[str]:
        raise NotImplementedError("Method not implemented")

    def create_folder(self, parent_path: str, folder_name: str):
        raise NotImplementedError("Method not implemented")

    def create_database(
            self,
            parent_path: str,
            name: str,
            file_id: str | None,
            buffer_file: 'BufferFile',
            comment: str,
            content_type: str,
            reset_database_id: bool,
            monitor: TaskMonitor,
            user: str
    ) -> 'DatabaseItem':
        raise NotImplementedError("Method not implemented")

    def create_data_file(
            self,
            parent_path: str,
            name: str,
            istream: InputStream | None,
            comment: str,
            content_type: str,
            monitor: TaskMonitor
    ) -> 'DataFileItem':
        raise NotImplementedError("Method not implemented")

    def delete_folder(self, folder_path: str):
        raise NotImplementedError("Method not implemented")

    def move_folder(
            self,
            parent_path: str,
            folder_name: str,
            new_parent_path: str
    ):
        raise NotImplementedError("Method not implemented")

    def rename_folder(
            self,
            parent_path: str,
            folder_name: str,
            new_folder_name: str
    ):
        raise NotImplementedError("Method not implemented")

    def move_item(
            self,
            folder_path: str,
            name: str,
            new_folder_path: str,
            new_name: str
    ):
        raise NotImplementedError("Method not implemented")

    def add_file_system_listener(self, listener):
        pass

    def remove_file_system_listener(self, listener):
        pass

    def folder_exists(self, folder_path: str) -> bool:
        raise NotImplementedError("Method not implemented")

    def file_exists(self, folder_path: str, name: str) -> bool:
        raise NotImplementedError("Method not implemented")

    def is_shared(self) -> bool:
        raise NotImplementedError("Method not implemented")

    def dispose(self):
        pass
