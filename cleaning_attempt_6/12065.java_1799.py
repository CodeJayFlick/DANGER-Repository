class RelocationDBAdapter:
    TYPE_ COL = 0
    VALUE_COL = 1
    BYTES_COL = 2
    SYMBOL_NAME_COL = 3

    TABLE_NAME = "Relocations"

    SCHEMA = {
        'Address': {'type': int},
        'Values': {'type': str, 'length': -1},
        'Bytes': {'type': bytes, 'length': -1},
        'Symbol Name': {'type': str}
    }

    @staticmethod
    def get_adapter(db_handle, open_mode, addr_map, monitor):
        if open_mode == "CREATE":
            return RelocationDBAdapterV4(db_handle, addr_map, True)

        try:
            adapter = RelocationDBAdapterV4(db_handle, addr_map, False)
            if addr_map.is_upgraded():
                raise VersionException(True)
            return adapter
        except VersionException as e:
            if not e.is_upgradable() or open_mode == "UPDATE":
                raise e

            read_only_adapter = find_readonly_adapter(db_handle, addr_map)

            if open_mode == "UPGRADE":
                adapter = upgrade(db_handle, addr_map, read_only_adapter, monitor)
            return adapter


    @staticmethod
    def find_readonly_adapter(handle, addr_map):
        try:
            return RelocationDBAdapterV3(handle, addr_map, False)
        except VersionException as e:
            # Try the next version
            pass

        try:
            return RelocationDBAdapterV2(handle, addr_map)
        except VersionException as e:
            # Try the next version
            pass

        try:
            return RelocationDBAdapterV1(handle, addr_map)
        except VersionException as e:
            # Try the next version
            pass

        return RelocationDBAdapterNoTable()


    @staticmethod
    def upgrade(db_handle, addr_map, old_adapter, monitor):
        old_addr_map = addr_map.get_old_address_map()

        tmp_handle = db_handle.copy()
        try:
            tmp_handle.start_transaction()

            adapter = RelocationDBAdapterV4(tmp_handle, addr_map, True)
            iterator = old_adapter.iterator()
            while iterator.has_next():
                record = iterator.next()
                address = old_addr_map.decode_address(record.key())
                values = BinaryCodedField((BinaryField)record.get_value(1))
                adapter.add(address, record.get_int_value(0), values.get_long_array(), None, None)

            db_handle.delete_table(TABLE_NAME)
            new_adapter = RelocationDBAdapterV4(db_handle, addr_map, True)

            iterator = adapter.iterator()
            while iterator.has_next():
                record = iterator.next()
                binary_coded_field = BinaryCodedField((BinaryField)record.get_value(1))
                new_adapter.add(record.key(), record.get_int_value(0), binary_coded_field.get_long_array(), None, None)
            return new_adapter
        finally:
            tmp_handle.close()


    def add(self):
        pass


    def remove(self):
        pass


    def get(self):
        pass


    def iterator(self):
        pass


    def iterator(self):
        pass


    def getVersion(self):
        pass


    def getRecordCount(self):
        pass


class RecordIteratorAdapter:
    def __init__(self, it):
        self.it = it

    def delete(self):
        return self.it.delete()


    def hasNext(self):
        return self.it.hasNext()


    def hasPrevious(self):
        return self.it.hasPrevious()


    def next(self):
        record = self.it.next()
        # Adapt the record
        pass


    def previous(self):
        record = self.it.previous()
        # Adapt the record
        pass

