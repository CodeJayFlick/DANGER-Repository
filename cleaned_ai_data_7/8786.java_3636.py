class VTAssociationTableDBAdapterV0:
    def __init__(self, db_handle):
        self.table = db_handle.create_table(TABLE_NAME, TABLE_SCHEMA, TABLE_INDEXES)

    def __init__(self, db_handle, open_mode, task_monitor):
        if not hasattr(self, 'table'):
            self.table = db_handle.get_table(TABLE_NAME)
            if self.table is None:
                raise VersionException("Missing Table: " + TABLE_NAME)
            elif self.table.schema.version != 0:
                raise VersionException("Expected version 0 for table " + TABLE_NAME +
                                       " but got " + str(self.table.schema.version))

    def insert_record(self, source_address_id, destination_address_id, association_type,
                      locked_status, vote_count):
        record = self.table.create_record()
        record.set_long_value(SOURCE_ADDRESS_COLUMN, source_address_id)
        record.set_long_value(DESTINATION_ADDRESS_COLUMN, destination_address_id)
        record.set_byte_value(TYPE_COLUMN, int(association_type))
        record.set_byte_value(STATUS_COLUMN, int(locked_status))
        record.set_int_value(VOTE_COUNT_COLUMN, vote_count)
        self.table.put_record(record)
        return record

    def delete_record(self, key):
        self.table.delete_record(key)

    def get_record(self, key):
        return self.table.get_record(key)

    def get_record_count(self):
        return self.table.record_count()

    def get_records(self):
        return self.table.iterator()

    def get_records_for_destination_address(self, address_id):
        long_field = LongField(address_id)
        return self.table.index_iterator(DESTINATION_ADDRESS_COLUMN, long_field, long_field, True)

    def get_records_for_source_address(self, address_id):
        long_field = LongField(address_id)
        return self.table.index_iterator(SOURCE_ADDRESS_COLUMN, long_field, long_field, True)

    def get_related_association_records_by_source_and_destination_address(self, source_address_id,
                                                                         destination_address_id):
        record_set = set()
        iterator = self.get_records_for_source_address(source_address_id)
        while iterator.has_next():
            record_set.add(iterator.next())
        iterator = self.get_records_for_destination_address(destination_address_id)
        while iterator.has_next():
            record_set.add(iterator.next())
        return record_set

    def get_related_association_records_by_source_address(self, source_address_id):
        record_set = set()
        iterator = self.get_records_for_source_address(source_address_id)
        while iterator.has_next():
            record_set.add(iterator.next())
        return record_set

    def get_related_association_records_by_destination_address(self, destination_address_id):
        record_set = set()
        iterator = self.get_records_for_destination_address(destination_address_id)
        while iterator.has_next():
            record_set.add(iterator.next())
        return record_set

    def update_record(self, record):
        self.table.put_record(record)

    def remove_association(self, id):
        self.table.delete_record(id)


class LongField:
    def __init__(self, value):
        self.value = value


class VersionException(Exception):
    pass
