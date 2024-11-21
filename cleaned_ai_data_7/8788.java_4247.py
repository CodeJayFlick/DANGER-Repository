class VTMatchMarkupItemTableDBAdapter:
    TABLE_NAME = "MatchMarkupItemTable"
    TABLE_SCHEMA = Schema(0, "Key", MarkupTableDescriptor().get_column_fields(), MarkupTableDescriptor().get_column_names())

    INDEXED_COLUMNS = MarkupTableDescriptor().get_indexed_columns()

    @staticmethod
    def create_adapter(db_handle):
        return VTMatchMarkupItemTableDBAdapterV0(db_handle)

    @staticmethod
    def get_adapter(db_handle, open_mode, monitor):
        try:
            return VTMatchMarkupItemTableDBAdapterV0(db_handle, open_mode, monitor)
        except VersionException as e:
            raise

    def get_records(self) -> 'RecordIterator':
        pass  # implement this method in the subclass

    def remove_match_markup_item_record(self, key: int):
        pass  # implement this method in the subclass

    def get_record(self, key: int) -> DBRecord:
        pass  # implement this method in the subclass

    def get_records(self, association_key: int) -> 'RecordIterator':
        pass  # implement this method in the subclass

    def update_record(self, record: DBRecord):
        pass  # implement this method in the subclass

    def get_record_count(self) -> int:
        pass  # implement this method in the subclass

    def create_markup_item_record(self, markup_item: MarkupItemStorage) -> DBRecord:
        pass  # implement this method in the subclass


class MarkupTableDescriptor:
    ASSOCIATION_KEY_COL = TableColumn(LongField.INSTANCE, True)
    ADDRESS_SOURCE_COL = TableColumn(StringField.INSTANCE)
    DESTINATION_ADDRESS_COL = TableColumn(LongField.INSTANCE)
    MARKUP_TYPE_COL = TableColumn(ShortField.INSTANCE)
    SOURCE_ADDRESS_COL = TableColumn(LongField.INSTANCE)
    SOURCE_VALUE_COL = TableColumn(StringField.INSTANCE)
    ORIGINAL_DESTINATION_VALUE_COL = TableColumn(StringField.INSTANCE)
    STATUS_COL = TableColumn(ByteField.INSTANCE)
    STATUS_DESCRIPTION_COL = TableColumn(StringField.INSTANCE)

    INSTANCE = MarkupTableDescriptor()


class Schema:
    def __init__(self, column_count: int, table_name: str):
        self.column_count = column_count
        self.table_name = table_name

    @property
    def get_column_fields(self) -> list:
        pass  # implement this method in the subclass

    @property
    def get_column_names(self) -> list:
        pass  # implement this method in the subclass


class VTMatchMarkupItemTableDBAdapterV0(VTMatchMarkupItemTableDBAdapter):
    def __init__(self, db_handle: DBHandle):
        self.db_handle = db_handle

    # implement other methods as needed
