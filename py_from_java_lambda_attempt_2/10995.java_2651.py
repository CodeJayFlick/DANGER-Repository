Here is the translation of the Java interface `ContentHandler` into a Python class:

```Python
class ContentHandler:
    UNKNOWN_CONTENT = "Unknown-File"
    MISSING_CONTENT = "Missing-File"

    def create_file(self, fs: 'FileSystem', userfs: 'FileSystem', path: str, name: str,
                    domain_object: 'DomainObject', monitor: 'TaskMonitor') -> int:
        # Implement the method
        pass

    def get_immutable_object(self, item: 'FolderItem', consumer: object, version: int,
                             min_change_version: int, monitor: 'TaskMonitor') -> 'DomainObjectAdapter':
        # Implement the method
        pass

    def get_read_only_object(self, item: 'FolderItem', version: int, ok_to_upgrade: bool,
                             consumer: object, monitor: 'TaskMonitor') -> 'DomainObjectAdapter':
        # Implement the method
        pass

    def get_domain_object(self, item: 'FolderItem', userfs: 'FileSystem', checkout_id: int,
                          ok_to_upgrade: bool, ok_to_recover: bool, consumer: object,
                          monitor: 'TaskMonitor') -> 'DomainObjectAdapter':
        # Implement the method
        pass

    def get_change_set(self, versioned_folder_item: 'FolderItem', older_version: int,
                       newer_version: int) -> 'ChangeSet':
        # Implement the method
        pass

    def get_merge_manager(self, results_obj: 'DomainObject', source_obj: 'DomainObject',
                          original_obj: 'DomainObject', latest_obj: 'DomainObject') -> object:
        # Implement the method
        pass

    def is_private_content_type(self) -> bool:
        # Implement the method
        return False  # Default implementation, you should implement this based on your needs.

    def get_content_type(self) -> str:
        # Implement the method
        return "Unknown-File"  # Default implementation, you should implement this based on your needs.

    def get_content_type_display_string(self) -> str:
        # Implement the method
        return self.get_content_type()  # Default implementation, you should implement this based on your needs.

    def get_icon(self) -> object:  # Assuming Icon is a Python class or module.
        # Implement the method
        pass

    def get_default_tool_name(self) -> str:
        # Implement the method
        return "Unknown-File"  # Default implementation, you should implement this based on your needs.

    def get_domain_object_class(self) -> type:  # Assuming DomainObject is a Python class.
        # Implement the method
        pass

    def save_user_data_file(self, associated_domain_obj: 'DomainObject', user_dbh: object,
                            user_fs: 'FileSystem', monitor: 'TaskMonitor') -> None:
        # Implement the method
        pass

    def remove_user_data_file(self, item: 'FolderItem', user_filesystem: 'FileSystem') -> None:
        # Implement the method
        pass
```

Note that I have used type hints for Python 3.5 and later versions. For earlier versions of Python, you can use comments to indicate the types instead.

Also note that some methods are not implemented as they require specific domain knowledge or implementation details which may vary based on your needs.