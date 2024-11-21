Here's your Java code translated into Python:

```Python
class RemoteFolderItem:
    def __init__(self, repository: 'RepositoryAdapter', item: 'RepositoryItem'):
        self.repository = repository
        self.parent_path = item.get_parent_path()
        self.item_name = item.name
        self.content_type = item.get_content_type()
        self.version = item.get_version()
        self.version_time = item.get_version_time()

    def get_item_type(self):
        raise NotImplementedError("getItemType is not implemented")

    @property
    def name(self) -> str:
        return self.item_name

    def refresh(self) -> 'RemoteFolderItem':
        item = self.repository.get_item(self.parent_path, self.item_name)
        if item is None:
            return None
        self.version = item.get_version()
        self.version_time = item.get_version_time()
        return self

    @property
    def file_id(self) -> str | None:
        item = self.repository.get_item(self.parent_path, self.item_name)
        if item is not None:
            return item.file_id
        return None

    def reset_file_id(self):
        raise NotImplementedError("resetFileID is not implemented")

    @property
    def content_type(self) -> str:
        return self.content_type

    @property
    def parent_path(self) -> str:
        return self.parent_path

    @property
    def path_name(self) -> str:
        if len(self.parent_path) != 1:
            self.parent_path += '/'
        return f"{self.parent_path}{self.item_name}"

    def is_read_only(self):
        raise NotImplementedError("isReadOnly is not implemented")

    def set_read_only(self, state: bool):
        raise NotImplementedError("setReadOnly is not implemented")

    @property
    def content_type_version(self) -> int:
        raise NotImplementedError("getContentTypeVersion is not implemented")

    def set_content_type_version(self, version: int):
        raise NotImplementedError("setContentTypeVersion is not implemented")

    @property
    def last_modified(self) -> float | None:
        return self.version_time

    @property
    def current_version(self) -> int:
        return self.version

    def is_versioned(self) -> bool:
        return self.version != -1

    def get_versions(self) -> list['Version']:
        raise NotImplementedError("getVersions is not implemented")

    def delete(self, ver: int, user: str):
        self.repository.delete_item(self.parent_path, self.item_name, ver)

    @property
    def checked_out(self) -> bool:
        raise NotImplementedError("isCheckedOut is not implemented")

    @property
    def checked_out_exclusive(self) -> bool:
        raise NotImplementedError("isCheckedOutExclusive is not implemented")

    def checkout(self, checkout_type: 'CheckoutType', user: str, project_path: str):
        return self.repository.checkout(self.parent_path, self.item_name, checkout_type, project_path)

    def terminate_checkout(self, checkout_id: int | float, notify: bool) -> None:
        raise NotImplementedError("terminateCheckout is not implemented")

    def get_checkout(self, checkout_id: int | float) -> 'ItemCheckoutStatus':
        return self.repository.get_checkout(self.parent_path, self.item_name, checkout_id)

    def get_checkouts(self) -> list['ItemCheckoutStatus']:
        raise NotImplementedError("getCheckouts is not implemented")

    def clear_checkout(self):
        raise NotImplementedError("clearCheckout is not implemented")
```

Please note that Python does not support checked exceptions like Java.