class SymbolDatabaseAdapterV0:
    SYMBOL_VERSION = 0
    V0_SYMBOL_NAME_COL = 0
    V0_SYMBOL_IS_DYNAMIC_COL = 1
    V0_SYMBOL_LOCAL_COL = 2
    V0_SYMBOL_PRIMARY_COL = 3
    V0_SYMBOL_ADDR_COL = 4

    def __init__(self, handle, addr_map):
        self.addr_map = addr_map.get_old_address_map()
        self.symbol_table = handle.get_table("SYMBOL_TABLE_NAME")
        if not self.symbol_table:
            raise VersionException("Missing Table: SYMBOL_TABLE_NAME")
        if self.symbol_table.schema.version != self.SYMBOL_VERSION:
            raise VersionException(False)

    def extract_local_symbols(self, handle, monitor):
        monitor.set_message("Extracting Local Symbols...")
        monitor.initialize(len(self.symbol_table))
        cnt = 0
        for rec in self.symbol_table.records():
            monitor.check_cancelled()
            if rec.get_boolean_value(V0_SYMBOL_LOCAL_COL) or \
               rec.get_boolean_value(V0_SYMBOL_IS_DYNAMIC_COL):
                SymbolManager.save_local_symbol(handle, rec.key,
                                                  rec.get_long_value(V0_SYMBOL_ADDR_COL),
                                                  rec.get_string(V0_SYMBOL_NAME_COL),
                                                  rec.get_boolean_value(V0_SYMBOL_PRIMARY_COL))
            monitor.set_progress(cnt + 1)
        return self.symbol_table.key

    def convert_record(self, record):
        if not record:
            return None
        if record.get_boolean_value(V0_SYMBOL_IS_DYNAMIC_COL) or \
           record.get_boolean_value(V0_SYMBOL_LOCAL_COL):
            raise AssertException("Unexpected Symbol")
        rec = SymbolDatabaseAdapter.SYMBOL_SCHEMA.create_record(record.key)
        symbol_name = record.get_string(V0_SYMBOL_NAME_COL)
        rec.set_string(SymbolDatabaseAdapter.SYMBOL_NAME_ COL, symbol_name)
        address_key = record.get_long_value(V0_SYMBOL_ADDR_COL)
        rec.set_long_value(SymbolDatabaseAdapter.SYMBOL_ADDR_ COL, address_key)

        if record.get_boolean_value(V0_SYMBOL_PRIMARY_COL):
            rec.set_long_value(SymbolDatabaseAdapter.SYMBOL_PRIMARY_ COL, address_key)

        rec.set_byte_value(SymbolDatabaseAdapter.SYMBOL_TYPE_ COL,
                           SymbolType.LABEL.getID())

        namespace_id = Namespace.GLOBAL_NAMESPACE_ID
        rec.set_long_value(SymbolDatabaseAdapter.SYMBOL_PARENT_ COL, namespace_id)

        rec.set_byte_value(SymbolDatabaseAdapter.SYMBOL_FLAGS_ COL,
                           SourceType.USER_DEFINED.ordinal())

        hash = self.compute_locator_hash(symbol_name, namespace_id, address_key)
        rec.set_field(SymbolDatabaseAdapter.SYMBOL_HASH_ COL, hash)

        return rec

    def create_symbol(self):
        raise UnsupportedOperationException()

    def remove_symbol(self, symbol_id):
        raise UnsupportedOperationException()

    def has_symbol(self, addr):
        raise UnsupportedOperationException()

    def get_symbol_ids(self, addr):
        raise UnsupportedOperationException()

    def get_symbol_record(self, symbol_id):
        return self.convert_record(self.symbol_table.get_record(symbol_id))

    def get_symbol_count(self):
        return len(self.symbol_table)

    def get_symbols_by_address(self, forward=True):
        return V0ConvertedRecordIterator(
            KeyToRecordIterator(self.symbol_table,
                                 AddressIndexPrimaryKeyIterator(self.symbol_table,
                                                              V0_SYMBOL_ADDR_COL,
                                                              self.addr_map,
                                                              forward)))

    def get_symbols_by_address_range(self, start_addr, end_addr, forward=True):
        return V0ConvertedRecordIterator(
            KeyToRecordIterator(self.symbol_table,
                                 AddressIndexPrimaryKeyIterator(self.symbol_table,
                                                              V0_SYMBOL_ADDR_COL,
                                                              self.addr_map,
                                                              start_addr,
                                                              end_addr,
                                                              forward)))

    def update_symbol_record(self, record):
        raise UnsupportedOperationException()

    def get_symbols_by_namespace(self, id):
        if id == Namespace.GLOBAL_NAMESPACE_ID:
            return self.get_symbols()
        return None

    class V0ConvertedRecordIterator:
        def __init__(self, sym_iter):
            self.sym_iter = sym_iter
            self.rec = None

        def has_next(self):
            while not self.rec and self.sym_iter.has_next():
                self.rec = self.sym_iter.next()
                if self.rec.get_boolean_value(V0_SYMBOL_LOCAL_COL) or \
                   self.rec.get_boolean_value(V0_SYMBOL_IS_DYNAMIC_COL):
                    self.rec = None
            return bool(self.rec)

        def has_previous(self):
            raise UnsupportedOperationException()

        def next(self):
            if self.has_next():
                rec = self.rec
                self.rec = None
                return SymbolDatabaseAdapterV0.convert_record(rec)
            return None

    # Other methods...

class V0ConvertedRecordIterator:
    pass

# ...other classes...
