import os
from urllib.parse import urlparse

class Resource:
    def __init__(self):
        pass

    @staticmethod
    def get_resource(name: str) -> 'Resource':
        raise NotImplementedError("Subclasses must implement this method")

    @property
    def absolute_path(self) -> str:
        raise NotImplementedError("Subclasses must implement this property")

    def list_files(self) -> list:
        raise NotImplementedError("Subclasses must implement this method")

    def list_files(self, filter: callable) -> list:
        raise NotImplementedError("Subclasses must implement this method")

    @property
    def name(self) -> str:
        raise NotImplementedError("Subclasses must implement this property")

    def is_directory(self) -> bool:
        raise NotImplementedError("Subclasses must implement this method")

    @property
    def parent(self) -> 'Resource':
        raise NotImplementedError("Subclasses must implement this property")

    def to_url(self) -> str:
        raise NotImplementedError("Subclasses must implement this method")

    def last_modified(self) -> int:
        raise NotImplementedError("Subclasses must implement this method")

    def get_input_stream(self) -> bytes:
        raise NotImplementedError("Subclasses must implement this method")

    def delete(self) -> bool:
        raise NotImplementedError("Subclasses must implement this method")

    def exists(self) -> bool:
        raise NotImplementedError("Subclasses must implement this method")

    @property
    def canonical_path(self) -> str:
        raise NotImplementedError("Subclasses must implement this property")

    def is_file(self) -> bool:
        raise NotImplementedError("Subclasses must implement this method")

    @property
    def file_system_root(self) -> 'Resource':
        raise NotImplementedError("Subclasses must implement this property")

    def to_uri(self) -> str:
        raise NotImplementedError("Subclasses must implement this method")

    def get_file_system_root(self) -> str:
        return urlparse(self.to_url()).path

    @property
    def canonical_resource(self) -> 'Resource':
        raise NotImplementedError("Subclasses must implement this property")
