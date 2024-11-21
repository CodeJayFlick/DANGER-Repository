Here is the translation of the Java code into Python:

```Python
class SymbolDatabaseAdapter:
    SYMBOL_TABLE_NAME = "Symbols"
    SYMBOL_NAME_COL = 0
    SYMBOL_ADDR_COL = 1
    SYMBOL_PARENT_COL = 2
    SYMBOL_TYPE_COL = 3
    SYMBOL_STRING_DATA_COL = 4
    SYMBOL_FLAGS_COL = 5

    # sparse fields - the following fields are not always applicable so they don't consume space in the database if they aren't used.
    SYMBOL_HASH_COL = 6
    SYMBOL_PRIMARY_COL = 7
    SYMBOL_DATATYPE_COL = 8
    SYMBOL_VAROFFSET_COL = 9

    def __init__(self, db_handle):
        self.db_handle = db_handle

    @staticmethod
    def get_adapter(db_handle, open_mode, addr_map, monitor):
        if open_mode == "CREATE":
            return SymbolDatabaseAdapterV3(db_handle, addr_map, True)

        try:
            adapter = SymbolDatabaseAdapterV3(db_handle, addr_map, False)
            return adapter

        except VersionException as e:
            if not e.is_upgradable() or open_mode == "UPDATE":
                raise e
            adapter = find_readonly_adapter(db_handle, addr_map)
            if open_mode == "UPGRADE":
                adapter = upgrade(db_handle, addr_map, adapter, monitor)

            elif isinstance(adapter, SymbolDatabaseAdapterV0):
                # Upgrade required - read-only use not supported
                raise e

            return adapter

    @staticmethod
    def find_readonly_adapter(handle, addr_map):
        try:
            return SymbolDatabaseAdapterV2(handle, addr_map.get_old_address_map())

        except VersionException as e1:
            pass  # failed try older version

        try:
            return SymbolDatabaseAdapterV1(handle, addr_map.get_old_address_map())

        except VersionException as e1:
            pass  # failed try older version

        try:
            return SymbolDatabaseAdapterV0(handle, addr_map.get_old_address_map())

        except VersionException as e1:
            raise VersionException(False)

    @staticmethod
    def upgrade(db_handle, addr_map, old_adapter, monitor):
        monitor.set_message("Upgrading Symbol Table...")
        monitor.initialize(old_adapter.get_symbol_count() * 2)

        try:
            tmp_adapter = copy_to_temp_and_fixup_records(addr_map, old_adapter, db_handle, monitor)
            return new_adapter

        finally:
            db_handle.delete_table(SymbolDatabaseAdapter.SYMBOL_TABLE_NAME)

    @staticmethod
    def compute_locator_hash(name, namespace_id, address_key):
        if not name:
            return None  # Default functions have no name, no point in storing a hash for those.

        long_name_namespace_hash = hash((name, namespace_id))
        combined_hash = (long_name_namespace_hash << 32) | (address_key & 0xFFFFFFFFL)
        return combined_hash

    @staticmethod
    def get_primary_filter_record_iterator(it):
        query = lambda record: not record.get_value(SymbolDatabaseAdapter.SYMBOL_PRIMARY_COL).is_null()
        return QueryRecordIterator(it, query)

class SymbolDatabaseAdapterV3:
    pass

class RecordIterator:
    pass

class DBRecord:
    pass

class Table:
    pass
```

Please note that this is a direct translation of the Java code into Python. It may not be perfect and might require some adjustments to work correctly in your specific use case.