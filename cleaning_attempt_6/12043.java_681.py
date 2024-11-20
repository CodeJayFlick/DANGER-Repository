class FromAdapterV0:
    def __init__(self, handle, create, addr_map, err_handler):
        self.addr_map = addr_map
        self.err_handler = err_handler
        if create:
            table = handle.create_table("FROM_REFS_TABLE_NAME", "FROM_REFS_SCHEMA")
        else:
            try:
                table = handle.get_table("FROM_REFS_TABLE_NAME")
                if table is None:
                    raise VersionException(f"Missing Table: {FROM_REFS_TABLE_NAME}")
                elif table.schema.version != 0:
                    raise VersionException(VersionException.NEWER_VERSION, False)
            except Exception as e:
                print(e)

    def create_ref_list(self, program_db, cache, from_addr):
        return RefListV0(from_addr, self, self.addr_map, program_db, cache, True)

    def get_ref_list(self, program_db, cache, from_addr, from_addr_long):
        try:
            rec = table.get_record(from_addr_long)
            if rec is not None:
                if rec.binary_data("REF_DATA_COL") is None:
                    return BigRefListV0(rec, self, self.addr_map, program_db, cache, True)
                else:
                    return RefListV0(rec, self, self.addr_map, program_db, cache, True)
            else:
                return None
        except Exception as e:
            print(e)

    def has_ref_from(self, from_addr):
        try:
            return table.has_record(from_addr)
        except Exception as e:
            print(e)

    def create_record(self, key_long, num_refs_int, ref_level_byte, ref_data_bytes):
        rec = FROM_REFS_SCHEMA.create_record(key_long)
        rec.set_value("REF_COUNT_COL", num_refs_int)
        rec.set_binary_data("REF_DATA_COL", ref_data_bytes)
        table.put_record(rec)
        return rec

    def get_record(self, key_long):
        try:
            return table.get_record(key_long)
        except Exception as e:
            print(e)

    def put_record(self, record_dbrecord):
        try:
            table.put_record(record_dbrecord)
        except Exception as e:
            print(e)

    def remove_record(self, key_long):
        try:
            table.delete_record(key_long)
        except Exception as e:
            print(e)

    def get_from_iterator(self, forward_bool):
        return AddressKeyAddressIterator(AddressKeyIterator(table, self.addr_map, forward_bool), forward_bool, self.addr_map, self.err_handler)

    def get_from_iterator(self, start_addr_address, forward_bool):
        return AddressKeyAddressIterator(AddressKeyIterator(table, self.addr_map, start_addr_address, forward_bool), forward_bool, self.addr_map, self.err_handler)

    def get_from_iterator(self, set_setview, forward_bool):
        return AddressKeyAddressIterator(AddressKeyIterator(table, self.addr_map, set, set.min_address(), forward_bool), forward_bool, self.addr_map, self.err_handler)

    def get_record_count(self):
        try:
            return table.get_record_count()
        except Exception as e:
            print(e)
