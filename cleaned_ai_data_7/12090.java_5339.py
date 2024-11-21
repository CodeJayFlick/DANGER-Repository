class LabelHistoryAdapterV0:
    def __init__(self, handle, create):
        if create:
            self.table = handle.create_table("LABEL_HISTORY_TABLE_NAME", "LABEL_HISTORY_SCHEMA", [1])
        else:
            try:
                self.table = handle.get_table("LABEL_HISTORY_TABLE_NAME")
                if not self.table:
                    raise VersionException(True)
                elif self.table.schema_version != 0:
                    raise VersionException(False, True)
            except Exception as e:
                print(f"Error: {e}")
        
        self.user_name = SystemUtilities.get_user_name()

class LabelHistoryAdapterV0Upgrade:
    @staticmethod
    def upgrade(db_handle, addr_map, old_adapter, monitor):
        try:
            tmp_handle = db_handle.start_transaction()
            
            monitor.set_message("Upgrading Label History...")
            monitor.initialize(old_adapter.record_count * 2)
            count = 0
            
            new_adapter = LabelHistoryAdapterV0(tmp_handle, True)
            record_iter = old_adapter.get_all_records()
            while record_iter.has_next():
                if monitor.is_cancelled():
                    raise CancelledException
                rec = record_iter.next()
                addr = old_addr_map.decode_address(rec[HISTORY_ADDR_COL])
                rec[HISTORY_ADDR_COL] = addr_map.key(addr, True)
                new_adapter.table.put_record(rec)
                monitor.set_progress(count + 1)
                
            db_handle.delete_table("LABEL_HISTORY_TABLE_NAME")
            LabelHistoryAdapterV0(new_adapter) = LabelHistoryAdapterV0(db_handle, True)

            record_iter = new_adapter.get_all_records()
            while record_iter.has_next():
                if monitor.is_cancelled():
                    raise CancelledException
                rec = record_iter.next()
                new_adapter.table.put_record(rec)
                monitor.set_progress(count + 1)
                
        finally:
            tmp_handle.close()

class LabelHistoryAdapterV0CreateRecord:
    def create_record(self, addr, action_id, label_str):
        try:
            rec = self.table.schema.create_record(self.table.key)
            
            rec[HISTORY_ADDR_COL] = addr
            rec[HISTORY_ACTION_COL] = action_id
            rec[HISTORY_LABEL_COL] = label_str
            rec[HISTORY_USER_COL] = self.user_name
            rec[HISTORY_DATE_COL] = int((datetime.datetime.now() - datetime.datetime(1970, 1, 1)).total_seconds())
            
            self.table.put_record(rec)
        except Exception as e:
            print(f"Error: {e}")

class LabelHistoryAdapterV0GetAllRecords:
    def get_all_records(self):
        return self.table.iterator()

class LabelHistoryAdapterV0GetRecordByAddress:
    def get_records_by_address(self, addr):
        try:
            field = LongField(addr)
            return self.table.index_iterator(HISTORY_ADDR_COL, field, field, True)
        except Exception as e:
            print(f"Error: {e}")

class LabelHistoryAdapterV0MoveAddress:
    def move_address(self, old_addr, new_addr):
        keys = self.table.find_records(LongField(old_addr), HISTORY_ADDR_COL)
        
        for key in keys:
            rec = self.table.get_record(key)
            rec[HISTORY_ADDR_COL] = new_addr
            self.table.put_record(rec)

class LabelHistoryAdapterV0MoveAddressRange:
    def move_address_range(self, from_addr, to_addr, length, addr_map, monitor):
        DatabaseTableUtils.update_indexed_address_field(self.table, HISTORY_ADDR_COL, addr_map, from_addr, to_addr, length, None, monitor)
        
if __name__ == "__main__":
    # Example usage
    handle = DBHandle()
    old_adapter = LabelHistoryAdapterV0(handle, True)
    
    new_adapter = LabelHistoryAdapterV0Upgrade.upgrade(handle, addr_map, old_adapter, TaskMonitor())
