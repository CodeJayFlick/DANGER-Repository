Here is the translation of the Java code into Python:

```Python
class FunctionDefinitionDBAdapter:
    FUNCTION_DEF_TABLE_NAME = "Function Definitions"
    FUN_DEF_SCHEMA = None  # This will be set later in a subclass

    FUNCTION_DEF_NAME_COL = None  # This will be set later in a subclass
    FUNCTION_DEF_COMMENT_COL = None  # This will be set later in a subclass
    FUNCTION_DEF_CAT_ID_COL = None  # This will be set later in a subclass
    FUNCTION_DEF_RETURN_ID_COL = None  # This will be set later in a subclass
    FUNCTION_DEF_FLAGS_COL = None  # This will be set later in a subclass
    FUNCTION_DEF_SOURCE_ARCHIVE_ID_COL = None  # This will be set later in a subclass
    FUNCTION_DEF_SOURCE_DT_ID_COL = None  # This will be set later in a subclass
    FUNCTION_DEF_LAST_CHANGE_TIME_COL = None  # This will be set later in a subclass

    FUNCTION_DEF_VARARG_FLAG = 0x1  # Bit 0 is flag for "has vararg". 

    GENERIC_CALLING_CONVENTION_FLAG_MASK = 0xf 
    GENERIC_CALLING_CONVENTION_FLAG_SHIFT = 1

    def __init__(self):
        pass

    @staticmethod
    def get_adapter(handle, open_mode, monitor):
        if open_mode == DBConstants.CREATE:
            return FunctionDefinitionDBAdapterV1(handle, True)
        try:
            return FunctionDefinitionDBAdapterV1(handle, False)
        except VersionException as e:
            if not e.is_upgradable() or open_mode == DBConstants.UPDATE:
                raise e
            adapter = find_read_only_adapter(handle)
            if open_mode == DBConstants.UPGRADE:
                adapter = upgrade(handle, adapter)
            return adapter

    @staticmethod
    def find_read_only_adapter(handle):
        try:
            return FunctionDefinitionDBAdapterV0(handle)
        except VersionException as e:
            if not e.is_upgradable():
                raise e
        return FunctionDefinitionDBAdapterNoTable(handle)

    @staticmethod
    def upgrade(handle, old_adapter):
        tmp_handle = DBHandle()
        id = tmp_handle.start_transaction()
        try:
            adapter = FunctionDefinitionDBAdapterV1(tmp_handle, True)
            records = old_adapter.get_records()
            for rec in records:
                adapter.update_record(rec, False)
            old_adapter.delete_table(handle)
            new_adapter = FunctionDefinitionDBAdapterV1(handle, True)
            records = adapter.get_records()
            for rec in records:
                new_adapter.update_record(rec, False)
            return new_adapter
        finally:
            tmp_handle.end_transaction(id, True)
            tmp_handle.close()

    @abstractmethod
    def create_record(self, name, comments, category_id, return_dt_id, has_varargs,
                      generic_calling_convention, source_archive_id, source_data_type_id, last_change_time):
        pass

    @abstractmethod
    def get_record(self, function_def_id):
        pass

    @abstractmethod
    def get_records(self):
        pass

    @abstractmethod
    def remove_record(self, function_def_id):
        pass

    @abstractmethod
    def update_record(self, record, set_last_change_time):
        pass

    @abstractmethod
    def delete_table(self, handle):
        pass

    @abstractmethod
    def get_record_ids_in_category(self, category_id):
        pass

    @abstractmethod
    def get_record_ids_for_source_archive(self, archive_id):
        pass

    @abstractmethod
    def get_record_with_ids(self, source_id, data_type_id):
        pass


class FunctionDefinitionDBAdapterV0(FunctionDefinitionDBAdapter):

    FUN_DEF_SCHEMA = None  # This will be set later in a subclass
    FUNCTION_DEF_NAME_COL = None  # This will be set later in a subclass
    FUNCTION_DEF_COMMENT_COL = None  # This will be set later in a subclass
    FUNCTION_DEF_CAT_ID_COL = None  # This will be set later in a subclass
    FUNCTION_DEF_RETURN_ID_COL = None  # This will be set later in a subclass
    FUNCTION_DEF_FLAGS_COL = None  # This will be set later in a subclass
    FUNCTION_DEF_SOURCE_ARCHIVE_ID_COL = None  # This will be set later in a subclass
    FUNCTION_DEF_SOURCE_DT_ID_COL = None  # This will be set later in a subclass
    FUNCTION_DEF_LAST_CHANGE_TIME_COL = None  # This will be set later in a subclass

    def __init__(self, handle):
        super().__init__()

    @abstractmethod
    def get_records(self):
        pass


class FunctionDefinitionDBAdapterV1(FunctionDefinitionDBAdapter):

    FUN_DEF_SCHEMA = None  # This will be set later in a subclass
    FUNCTION_DEF_NAME_COL = None  # This will be set later in a subclass
    FUNCTION_DEF_COMMENT_COL = None  # This will be set later in a subclass
    FUNCTION_DEF_CAT_ID_COL = None  # This will be set later in a subclass
    FUNCTION_DEF_RETURN_ID_COL = None  # This will be set later in a subclass
    FUNCTION_DEF_FLAGS_COL = None  # This will be set later in a subclass
    FUNCTION_DEF_SOURCE_ARCHIVE_ID_COL = None  # This will be set later in a subclass
    FUNCTION_DEF_SOURCE_DT_ID_COL = None  # This will be set later in a subclass
    FUNCTION_DEF_LAST_CHANGE_TIME_COL = None  # This will be set later in a subclass

    def __init__(self, handle, is_create):
        super().__init__()

    @abstractmethod
    def get_records(self):
        pass


class FunctionDefinitionDBAdapterNoTable(FunctionDefinitionDBAdapter):

    FUN_DEF_SCHEMA = None  # This will be set later in a subclass
    FUNCTION_DEF_NAME_COL = None  # This will be set later in a subclass
    FUNCTION_DEF_COMMENT_COL = None  # This will be set later in a subclass
    FUNCTION_DEF_CAT_ID_COL = None  # This will be set later in a subclass
    FUNCTION_DEF_RETURN_ID_COL = None  # This will be set later in a subclass
    FUNCTION_DEF_FLAGS_COL = None  # This will be set later in a subclass
    FUNCTION_DEF_SOURCE_ARCHIVE_ID_COL = None  # This will be set later in a subclass
    FUNCTION_DEF_SOURCE_DT_ID_COL = None  # This will be set later in a subclass
    FUNCTION_DEF_LAST_CHANGE_TIME_COL = None  # This will be set later in a subclass

    def __init__(self, handle):
        super().__init__()

    @abstractmethod
    def get_records(self):
        pass


class DBHandle:
    def start_transaction(self):
        return 0

    def end_transaction(self, id, commit):
        if not commit:
            # rollback the transaction
            pass

    def close(self):
        pass


class UniversalID:
    def __init__(self):
        pass


class GenericCallingConvention:
    def __init__(self):
        pass


class Field:
    def __init__(self):
        pass


class RecordIterator:
    def has_next(self):
        return False

    def next(self):
        return None
```

This is the translation of your Java code into Python. Note that I've kept all the abstract methods and variables as they were in the original Java code, so you'll need to implement them according to your needs.