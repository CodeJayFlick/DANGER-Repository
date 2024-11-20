Here is a translation of the Java code into equivalent Python:

```Python
class VTAssociationTableDBAdapter:
    TABLE_NAME = "AssociationTable"
    TABLE_SCHEMA = {"Key": None}
    TABLE_INDEXES = []

    @staticmethod
    def create_adapter(db_handle):
        return VTAssociationTableDBAdapterV0(db_handle)

    @staticmethod
    def get_adapter(db_handle, open_mode=None, monitor=None):
        if open_mode is not None and monitor is not None:
            return VTAssociationTableDBAdapterV0(db_handle, open_mode, monitor)
        else:
            return VTAssociationTableDBAdapterV0(db_handle)

    def __init__(self):
        pass

    abstract def insert_record(self, source_address_id: int, destination_address_id: int,
                                type: str, status: str, vote_count: int) -> None:

    abstract def delete_record(self, source_address_id: int) -> None:
        pass

    abstract def get_records_for_source_address(self, source_address_id: int) -> list:
        pass

    abstract def get_records_for_destination_address(self, destination_address_id: int) -> list:
        pass

    abstract def get_record_count(self) -> int:
        pass

    abstract def get_records(self) -> list:
        pass

    abstract def get_record(self, key: int) -> dict:
        pass

    abstract def get_related_association_records_by_source_and_destination_address(
            self, source_address_id: int, destination_address_id: int
    ) -> set:
        pass

    abstract def get_related_association_records_by_source_address(self, source_address_id: int) -> set:
        pass

    abstract def get_related_association_records_by_destination_address(self, destination_address_id: int) -> set:
        pass

    abstract def update_record(self, record: dict) -> None:
        pass

    abstract def remove_associaiton(self, id: int) -> None:
        pass


class AssociationTableDescriptor:
    SOURCE_ADDRESS_COL = {"type": "long", "indexed": True}
    DESTINATION_ADDRESS_COL = {"type": "long", "indexed": True}
    TYPE_COL = {"type": "byte"}
    STATUS_COL = {"type": "byte"}
    APPLIED_STATUS_COL = {"type": "byte"}
    VOTE_COUNT_COL = {"type": "int"}

    @staticmethod
    def get_instance():
        return AssociationTableDescriptor()


class VTAssociationTableDBAdapterV0(VTAssociationTableDBAdapter):
    def __init__(self, db_handle: object, open_mode=None, monitor=None):
        super().__init__()
```

Please note that this is a translation of the Java code into Python. The actual implementation may vary depending on your specific requirements and constraints.