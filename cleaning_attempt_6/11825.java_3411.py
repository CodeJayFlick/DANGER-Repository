class CommentsDBAdapter:
    COMMENTS_TABLE_NAME = "Comments"
    NAMES = ["Pre", "Post", "EOL", "Plate", "Repeatable"]
    
    def __init__(self, db_handle):
        self.db_handle = db_handle

    @staticmethod
    def get_adapter(db_handle, open_mode, addr_map, monitor=None):
        if open_mode == 1:
            return CommentsDBAdapterV1(db_handle, addr_map, True)
        
        try:
            adapter = CommentsDBAdapterV1(db_handle, addr_map, False)
            if addr_map.is_upgraded():
                raise VersionException(True)
            return adapter
        except VersionException as e:
            if not e.is_upgradable() or open_mode == 2:
                raise e
            read_only_adapter = find_readonly_adapter(db_handle, addr_map)
            if open_mode == 3:
                adapter = upgrade(db_handle, addr_map, read_only_adapter, monitor)
            return adapter

    @staticmethod
    def find_readonly_adapter(handle, addr_map):
        try:
            return CommentsDBAdapterV1(handle, addr_map.get_old_address_map(), False)
        except VersionException as e:
            pass
        
        return CommentsDBAdapterV0(handle, addr_map)

    @staticmethod
    def upgrade(db_handle, addr_map, old_adapter, monitor=None):
        old_addr_map = addr_map.get_old_address_map()
        
        tmp_handle = db_handle.copy()
        try:
            tmp_handle.start_transaction()

            monitor.set_message("Upgrading Comments...")
            monitor.initialize(old_adapter.get_record_count() * 2)
            count = 0

            comments_db_adapter = CommentsDBAdapterV1(tmp_handle, addr_map, True)
            record_iterator = old_adapter.get_records()
            while record_iterator.has_next():
                monitor.check_cancelled()
                db_record = record_iterator.next()
                address = old_addr_map.decode_address(db_record.key())
                db_record.set_key(addr_map.encode_address(address))
                comments_db_adapter.update_record(db_record)
                monitor.increment_progress(count + 1)

            tmp_handle.delete_table(CommentsDBAdapter.COMMENTS_TABLE_NAME)
            new_adapter = CommentsDBAdapterV1(tmp_handle, addr_map, True)

            record_iterator = comments_db_adapter.get_records()
            while record_iterator.has_next():
                monitor.check_cancelled()
                db_record = record_iterator.next()
                new_adapter.update_record(db_record)
                monitor.increment_progress(count + 1)

            return new_adapter
        finally:
            tmp_handle.close()

    def get_record_count(self):
        # implement this method in the subclass
        pass

    def get_record(self, addr):
        # implement this method in the subclass
        pass

    def create_record(self, addr, comment_col, comment):
        # implement this method in the subclass
        pass

    def delete_record(self, addr):
        # implement this method in the subclass
        pass

    def delete_records(self, start_addr, end_addr):
        # implement this method in the subclass
        pass

    def update_record(self, db_record):
        # implement this method in the subclass
        pass

    def get_records(self):
        # implement this method in the subclass
        pass

    def get_keys(self, start_addr, end_addr, at_start=False):
        # implement this method in the subclass
        pass

    def put_record(self, db_record):
        # implement this method in the subclass
        pass

    def move_address_range(self, from_addr, to_addr, length, monitor=None):
        # implement this method in the subclass
        pass


class CommentsDBAdapterV0(CommentsDBAdapter):
    def get_records(self):
        # implement this method
        pass

    def update_record(self, db_record):
        # implement this method
        pass

    def delete_records(self, start_addr, end_addr):
        # implement this method
        pass


class CommentsDBAdapterV1(CommentsDBAdapter):
    def get_records(self):
        # implement this method
        pass

    def update_record(self, db_record):
        # implement this method
        pass

    def delete_records(self, start_addr, end_addr):
        # implement this method
        pass


class VersionException(Exception):
    def __init__(self, is_upgradable=False):
        self.is_upgradable = is_upgradable
