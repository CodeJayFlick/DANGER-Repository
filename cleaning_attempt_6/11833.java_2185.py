class DataDBAdapterV0:
    def __init__(self, handle, addr_map, create):
        self.addr_map = addr_map
        if create:
            self.data_table = handle.create_table("DATA_TABLE_NAME", "DATA_SCHEMA")
        else:
            try:
                self.data_table = handle.get_table("DATA_TABLE_NAME")
                if not self.data_table:
                    raise VersionException(f"Missing Table: {DATA_TABLE_NAME}")
                if self.data_table.schema.version != 0:
                    raise VersionException(VersionException.NEWER_VERSION, False)
            except Exception as e:
                print(e)

    def get_record_at_or_after(self, addr):
        try:
            iterator = AddressKeyRecordIterator(self.data_table, self.addr_map, addr, True)
            return next(iterator)
        except Exception as e:
            print(e)

    def get_record_at_or_before(self, addr):
        try:
            iterator = AddressKeyRecordIterator(self.data_table, self.addr_map, addr, False)
            return previous(iterator)
        except Exception as e:
            print(e)

    def get_record_after(self, addr):
        try:
            iterator = AddressKeyRecordIterator(self.data_table, self.addr_map, addr, False)
            return next(iterator)
        except Exception as e:
            print(e)

    def get_record(self, addr):
        try:
            return self.data_table.get_record(self.addr_map.key(addr, False))
        except Exception as e:
            print(e)

    def delete_record(self, key):
        try:
            self.data_table.delete_record(key)
        except Exception as e:
            print(e)

    def create_data(self, new_addr, data_type_id):
        try:
            key = self.addr_map.key(new_addr, True)
            record = DATA_SCHEMA.create_record(key)
            record.set_long_value(DATA_TYPE_ID_COL, data_type_id)
            self.data_table.put_record(record)
            return record
        except Exception as e:
            print(e)

    def delete_records(self, start, end):
        try:
            return AddressRecordDeleter.delete_records(self.data_table, self.addr_map, start, end)
        except Exception as e:
            print(e)

    def get_record_count(self):
        try:
            return self.data_table.get_record_count()
        except Exception as e:
            print(e)

    def get_keys(self, start, end, at_start=False):
        if at_start:
            iterator = AddressKeyIterator(self.data_table, self.addr_map, start, end, start, True)
        else:
            iterator = AddressKeyIterator(self.data_table, self.addr_map, start, end, end, False)
        return iterator

    def put_record(self, record):
        try:
            self.data_table.put_record(record)
        except Exception as e:
            print(e)

    def get_records(self):
        try:
            return AddressKeyRecordIterator(self.data_table, self.addr_map)
        except Exception as e:
            print(e)

    def move_address_range(self, from_addr, to_addr, length, monitor):
        try:
            DatabaseTableUtils.update_address_key(self.data_table, self.addr_map, from_addr, to_addr, length, monitor)
        except Exception as e:
            print(e)


class AddressKeyRecordIterator:
    def __init__(self, data_table, addr_map, start, forward=True):
        self.data_table = data_table
        self.addr_map = addr_map
        self.start = start
        self.forward = forward

    def next(self):
        if self.forward:
            return self.data_table.get_record(self.addr_map.key(self.start, True))
        else:
            return self.data_table.get_record(self.addr_map.key(self.start, False))

    def previous(self):
        if not self.forward:
            return self.next()
        else:
            raise Exception("Not implemented")


class AddressKeyIterator:
    def __init__(self, data_table, addr_map, start, end, at_start=False):
        self.data_table = data_table
        self.addr_map = addr_map
        self.start = start
        self.end = end
        self.at_start = at_start

    def __iter__(self):
        if self.at_start:
            yield from AddressKeyRecordIterator(self.data_table, self.addr_map, self.start)
        else:
            yield from AddressKeyRecordIterator(self.data_table, self.addr_map, self.end)


class VersionException(Exception):
    NEWER_VERSION = "Newer version"
