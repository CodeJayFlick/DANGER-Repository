from typing import TypeVar, Optional

class StoreWorker:
    def __init__(self):
        pass

    @property
    def contents_type(self) -> TypeVar('CONTENTS_TYPE'):
        raise NotImplementedError("Subclasses must implement this method")

    def to_store_on_reference_state(self, contents: object) -> bytes:
        """Returns the serialized representation of the on-reference part of the given contents-object."""
        raise NotImplementedError("Subclasses must implement this method")

    def to_store_global_state(self, contents: object) -> Optional[bytes]:
        """Returns the serialized representation of the global state part of the given contents-object."""
        raise NotImplementedError("Subclasses must implement this method")

    def value_from_store(self, on_reference_value: bytes, global_state: Optional[bytes]) -> object:
        """Deserializes a store-value into its original form"""
        raise NotImplementedError("Subclasses must implement this method")

    def get_id(self, contents: object) -> str:
        """Returns the ID of the given contents-object."""
        raise NotImplementedError("Subclasses must implement this method")

    def get_payload(self, contents: object) -> int:
        """Returns the payload of the given contents-object."""
        raise NotImplementedError("Subclasses must implement this method")

    def requires_global_state(self, contents: object) -> bool:
        """Indicates whether a global state is required for the given contents-object"""
        raise NotImplementedError("Subclasses must implement this method")

    @property
    def metadata_serializer(self):
        raise NotImplementedError("Subclasses must implement this method")
