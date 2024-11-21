Here is the translation of the given Java code into Python:

```Python
class FromAdapter:
    FROM_REFS_TABLE_NAME = "FROM REFS"
    FROM_REFS_SCHEMA = Schema(0, "From Address", [IntField(), BinaryField()], ["Number of Refs", "Ref Data"])

    REF_COUNT_COL = 0
    REF_DATA_COL = 1

    def __init__(self):
        pass

    @staticmethod
    def get_adapter(db_handle: 'DBObjectHandle', open_mode: int, addr_map: 'AddressMap', err_handler: 'ErrorHandler', monitor: 'TaskMonitor') -> 'FromAdapter':
        if open_mode == DBConstants.CREATE:
            return FromAdapterV0(db_handle, True, addr_map, err_handler)

        try:
            adapter = FromAdapterV0(db_handle, False, addr_map, err_handler)
            if addr_map.is_upgraded():
                raise VersionException(True)
            return adapter
        except VersionException as e:
            if not e.is_upgradable() or open_mode == DBConstants.UPDATE:
                raise e

            read_only_adapter = FromAdapter.find_read_only_adapter(db_handle, addr_map, err_handler)

            if open_mode == DBConstants.UPGRADE:
                adapter = FromAdapter.upgrade(db_handle, addr_map, read_only_adapter, err_handler, monitor)
            return adapter
        except CancelledException as e:
            raise e

    @staticmethod
    def find_read_only_adapter(db_handle: 'DBObjectHandle', addr_map: 'AddressMap', err_handler: 'ErrorHandler') -> 'FromAdapter':
        try:
            return FromAdapterV0(db_handle, False, addr_map.get_old_address_map(), err_handler)
        except VersionException as e:
            pass

        return FromAdapterSharedTable(db_handle, addr_map, err_handler)

    @staticmethod
    def upgrade(db_handle: 'DBObjectHandle', addr_map: 'AddressMap', old_adapter: 'FromAdapter', err_handler: 'ErrorHandler', monitor: 'TaskMonitor') -> 'FromAdapter':
        try:
            tmp_handle = DBHandle()
            tmp_handle.start_transaction()

            monitor.set_message("Upgrading Memory References...")
            monitor.initialize(old_adapter.get_record_count() * 2)
            count = 0

            new_ref_list = RefListV0(None, None, old_adapter)

            addr_iter = old_adapter.get_from_iterator(True)
            while addr_iter.has_next():
                if monitor.is_cancelled():
                    raise CancelledException()

                from_addr = addr_iter.next()
                ref_list = old_adapter.get_ref_list(None, None, from_addr, addr_map.get_key(from_addr, False))
                refs = ref_list.get_all_refs()
                new_ref_list.add_refs(refs)
                monitor.set_progress(count + 1)

            db_handle.delete_table(FromAdapter.FROM_REFS_TABLE_NAME)
            adapter = FromAdapterV0(db_handle, True, addr_map, err_handler)

            addr_iter = old_adapter.get_from_iterator(True)
            while addr_iter.has_next():
                if monitor.is_cancelled():
                    raise CancelledException()

                from_addr = addr_iter.next()
                new_ref_list = RefListV0(from_addr, adapter, addr_map, None, None, True)
                refs = ref_list.get_all_refs()
                adapter.create_record(addr_map.get_key(from_addr, True), len(refs) if ref_list else 0, -1, ref_list.data if ref_list else None)
                monitor.set_progress(count + 1)

            return adapter
        finally:
            tmp_handle.close()

    def get_record_count(self):
        pass

    def create_ref_list(self, program: 'ProgramDB', cache: 'DBObjectCache[RefList]', from_addr: Address) -> RefList:
        pass

    def get_ref_list(self, program: 'ProgramDB', cache: 'DBObjectCache[RefList]', from_addr: Address, from_addr_long: long) -> RefList:
        pass

    def has_ref_from(self, from_addr: long) -> bool:
        pass

    def get_from_iterator(self, forward: bool) -> AddressIterator:
        pass

    def get_from_iterator(self, start_addr: Address, forward: bool) -> AddressIterator:
        pass

    def get_from_iterator(self, set_view: 'AddressSetView', forward: bool) -> AddressIterator:
        pass
```

Please note that the above Python code is not a direct translation of the given Java code. It's more like an equivalent implementation in Python with some modifications to fit into Python syntax and semantics.