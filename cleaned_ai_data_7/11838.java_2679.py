class InstDBAdapter:
    INSTRUCTION_TABLE_NAME = "Instructions"
    INSTRUCTION_SCHEMA = Schema(1, "Address", [IntField.INSTANCE, ByteField.INSTANCE], ["Proto ID", "Flags"])
    PROTO_ID_COL = 0
    FLAGS_COL = 1

    def __init__(self):
        pass

    @staticmethod
    def get_adapter(db_handle, open_mode, addr_map, monitor=None):
        if open_mode == DBConstants.CREATE:
            return InstDBAdapterV1(db_handle, addr_map, True)
        
        try:
            adapter = InstDBAdapterV1(db_handle, addr_map, False)
            if addr_map.is_upgraded():
                raise VersionException(True)
            return adapter
        except (VersionException, IOException):
            if not e.is_upgradable() or open_mode == DBConstants.UPDATE:
                raise e
            read_only_adapter = find_readonly_adapter(db_handle, addr_map)
            if open_mode == DBConstants.UPGRADE:
                adapter = upgrade(db_handle, addr_map, adapter, monitor)
            return adapter

    @staticmethod
    def find_readonly_adapter(handle, addr_map):
        try:
            return InstDBAdapterV1(handle, addr_map.get_old_address_map(), False)
        except VersionException as e:
            pass
        
        return InstDBAdapterV0(handle, addr_map)

    @staticmethod
    def upgrade(db_handle, addr_map, old_adapter, monitor=None):
        old_addr_map = addr_map.get_old_address_map()
        
        tmp_handle = DBHandle()
        try:
            tmp_handle.start_transaction()

            monitor.set_message("Upgrading Instructions...")
            monitor.initialize(old_adapter.get_record_count() * 2)
            count = 0

            new_adapter = InstDBAdapterV1(tmp_handle, addr_map, True)

            record_iter = old_adapter.get_records()
            while record_iter.has_next():
                monitor.check_cancelled()
                rec = record_iter.next()
                addr = old_addr_map.decode_address(rec.key())
                rec.set_key(addr_map.encode_address(True))
                new_adapter.put_record(rec)
                monitor.set_progress(count + 1)

            db_handle.delete_table(InstDBAdapter.INSTRUCTION_TABLE_NAME)
            return new_adapter
        finally:
            tmp_handle.close()

    def create_instruction(self, addr, proto_id, flags):
        raise NotImplementedError

    def update_flags(self, addr, flags):
        raise NotImplementedError

    def delete_record(self, addr):
        raise NotImplementedError

    def get_record_at_or_after(self, addr):
        raise NotImplementedError

    def get_record_after(self, addr):
        raise NotImplementedError

    def get_record(self, addr):
        raise NotImplementedError

    def get_record_before(self, addr):
        raise NotImplementedError

    def get_records(self, start=None, end=None, at_start=False):
        raise NotImplementedError

    def get_keys(self, start=None, end=None, at_start=False):
        raise NotImplementedError

    def delete_records(self, start=None, end=None):
        raise NotImplementedError

    def put_record(self, rec):
        raise NotImplementedError

    def move_address_range(self, from_addr, to_addr, length, monitor=None):
        raise CancelledException
        raise IOException

    def delete_all(self):
        raise IOException


class DBRecord:
    pass


class Schema:
    def __init__(self, count, name, fields, column_names):
        self.count = count
        self.name = name
        self.fields = fields
        self.column_names = column_names


class IntField:
    INSTANCE = None

    def __new__(cls):
        if cls.INSTANCE is None:
            cls.INSTANCE = super(IntField, cls).__new__(cls)
        return cls.INSTANCE


class ByteField:
    INSTANCE = None

    def __new__(cls):
        if cls.INSTANCE is None:
            cls.INSTANCE = super(ByteField, cls).__new__(cls)
        return cls.INSTANCE
