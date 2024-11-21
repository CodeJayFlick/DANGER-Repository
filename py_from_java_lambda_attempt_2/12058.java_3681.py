Here is the translation of the given Java code into Python:

```Python
class ToAdapterV1:
    def __init__(self, handle, create, addr_map, err_handler):
        self.addr_map = addr_map
        self.err_handler = err_handler
        if create:
            table = handle.create_table("TO_REFS_TABLE_NAME", "TO_REFS_SCHEMA")
        else:
            try:
                table = handle.get_table("TO_REFS_TABLE_NAME")
                if table is None:
                    raise VersionException(f"Missing Table: {TO_REFS_TABLE_NAME}")
                elif table.schema.version != 1:
                    version = table.schema.version
                    if version < 1:
                        raise VersionException(True)
                    else:
                        raise VersionException(VersionException.NEWER_VERSION, False)
            except Exception as e:
                self.err_handler.db_error(e)

    def create_ref_list(self, program, cache, to):
        return RefListV0(to, self, self.addr_map, program, cache, False)

    def get_ref_list(self, program, cache, to, to_addr):
        try:
            rec = table.get_record(to_addr)
            if rec is not None:
                if rec.binary_data("REF_DATA_COL") is None:
                    return BigRefListV0(rec, self, self.addr_map, program, cache, False)
                else:
                    return RefListV0(rec, self, self.addr_map, program, cache, False)
        except Exception as e:
            self.err_handler.db_error(e)

    def has_ref_to(self, to_addr):
        try:
            return table.has_record(to_addr)
        except Exception as e:
            self.err_handler.db_error(e)

    def create_record(self, key, num_refs, ref_level, ref_data):
        rec = TO_REFS_SCHEMA.create_record(key)
        rec.set_int_value("REF_COUNT_COL", num_refs)
        rec.set_binary_data("REF_DATA_COL", ref_data)
        rec.set_byte_value("REF_LEVEL_COL", ref_level)
        table.put_record(rec)
        return rec

    def get_record(self, key):
        try:
            return table.get_record(key)
        except Exception as e:
            self.err_handler.db_error(e)

    def put_record(self, record):
        try:
            table.put_record(record)
        except Exception as e:
            self.err_handler.db_error(e)

    def remove_record(self, key):
        try:
            table.delete_record(key)
        except Exception as e:
            self.err_handler.db_error(e)

    def get_to_iterator(self, forward):
        return AddressKeyAddressIterator(AddressKeyIterator(table, addr_map, forward), forward, addr_map, err_handler)

    def get_to_iterator(self, start_addr, forward):
        return AddressKeyAddressIterator(AddressKeyIterator(table, addr_map, start_addr, forward), forward, addr_map, err_handler)

    def get_to_iterator(self, set, forward):
        return AddressKeyAddressIterator(AddressKeyIterator(table, addr_map, set, set.min_address(), forward), forward, addr_map, err_handler)

    def get_old_namespace_addresses(self, addr_space):
        min_key = self.addr_map.get_key(OldGenericNamespaceAddress.MIN_ADDRESS(addr_space, OldGenericNamespaceAddress.OLD_MIN_NAMESPACE_ID), False)
        max_key = self.addr_map.get_key(OldGenericNamespaceAddress.MAX_ADDRESS(addr_space, OldGenericNamespaceAddress.OLD_MAX_NAMESPACE_ID), False)
        return MyAddressKeyAddressIterator(table.long_key_iterator(min_key, max_key, min_key))

    def get_record_count(self):
        return table.record_count

class AddressKeyAddressIterator:
    def __init__(self, key_iter, forward, addr_map, err_handler):
        self.key_iter = key_iter
        self.forward = forward
        self.addr_map = addr_map
        self.err_handler = err_handler

    def remove(self):
        raise UnsupportedOperationException()

    def has_next(self):
        try:
            return self.key_iter.has_next()
        except Exception as e:
            self.err_handler.db_error(e)
        return False

    def next(self):
        addr = None
        try:
            addr = self.addr_map.decode_address(next(self.key_iter))
        except NoSuchElementException as e:
            return None
        except Exception as e:
            pass  # Ignore
        return addr

class MyAddressKeyAddressIterator(AddressKeyAddressIterator):
    def __init__(self, key_iter):
        super().__init__(key_iter, True, None, None)
```

Note: The above Python code is a direct translation of the given Java code. It may not be perfect and might require some adjustments to work correctly in your specific use case.