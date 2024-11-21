class OldExtRefAdapter:
    EXT_REF_TABLE_NAME = "External References"
    EXT_REF_SCHEMA = {
        'Key': {'type': int},
        'From Address': {'type': int},
        'Op Index': {'type': int},
        'User Defined': {'type': bool},
        'External Name ID': {'type': int},
        'Label': {'type': str},
        'External To': {'type': int},
        'External To Exists': {'type': bool}
    }

    FROM_ADDR_COL = 0
    OP_INDEX_COL = 1
    USER_DEFINED_COL = 2
    EXT_NAME_ID_COL = 3
    LABEL_COL = 4
    EXT_TO_ADDR_COL = 5
    EXT_ADDR_EXITS_COL = 6

    def __init__(self, handle):
        self.ref_table = handle.get_table(self.EXT_REF_TABLE_NAME)
        if not self.ref_table:
            raise VersionException("Missing Table: " + self.EXT_REF_TABLE_NAME)

    def get_records(self):
        return iter(self.ref_table.records())

    def get_record_count(self):
        return len(list(self.ref_table.records()))

    def move_table(self, handle, monitor):
        tmp_handle = handle.scratch_pad
        new_ref_table = tmp_handle.create_table(self.EXT_REF_TABLE_NAME, self.EXT_REF_SCHEMA)

        monitor.set_message("Processing Old External References...")
        monitor.initialize(len(self.ref_table.records()))
        count = 0

        for record in self.ref_table.records():
            if monitor.is_cancelled:
                break
            new_ref_table.put_record(record)
            monitor.set_progress(count + 1)
            count += 1

        handle.delete_table(self.EXT_REF_TABLE_NAME)
        self.ref_table = new_ref_table


def get_adapter(db_handle, open_mode, monitor):
    adapter = OldExtRefAdapter(db_handle)

    if open_mode == 'upgrade':
        adapter.move_table(db_handle, monitor)

    return adapter
