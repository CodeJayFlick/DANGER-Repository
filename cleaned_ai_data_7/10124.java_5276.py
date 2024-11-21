class UnknownFolderItem:
    UNKNOWN_CONTENT_TYPE = "Unknown"

    def __init__(self, file_system, property_file):
        super().__init__()

    def length(self) -> int:
        return 0

    def update_checkout(self, versioned_folder_item: 'FolderItem', update_item: bool, monitor: 'TaskMonitor') -> None:
        raise UnsupportedOperationException()

    def checkout(self, user: str) -> 'ItemCheckoutStatus':
        raise IOException(f"{self.property_file.name} may not be checked-out, item may be corrupt")

    def terminate_checkout(self, checkout_id: int) -> None:
        pass

    def clear_checkout(self) -> None:
        pass

    def set_checkout(self, checkout_id: int, checkout_version: int, local_version: int) -> None:
        pass

    def get_checkout(self, checkout_id: int) -> 'ItemCheckoutStatus':
        return None

    def get_checkouts(self) -> list['ItemCheckoutStatus']:
        return []

    def get_versions(self) -> list[int]:
        raise IOException("History data is unavailable for " + self.property_file.name)

    def get_content_type(self) -> str:
        return self.UNKNOWN_CONTENT_TYPE

    def delete_minimum_version(self, user: str) -> None:
        raise UnsupportedOperationException("Versioning not supported for UnknownFolderItems")

    def delete_current_version(self, user: str) -> None:
        raise UnsupportedOperationException("Versioning not supported for UnknownFolderItems")

    def output(self, file_output: 'File', version: int, monitor: 'TaskMonitor') -> None:
        raise UnsupportedOperationException("Output not supported for UnknownFolderItems")

    def get_minimum_version(self) -> int:
        return -1

    def get_current_version(self) -> int:
        return -1

    def can_recover(self) -> bool:
        return False
