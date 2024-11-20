class VTMatchMarkupItemTableDBAdapterV0:
    def __init__(self, db_handle):
        self.table = db_handle.create_table(TABLE_NAME, TABLE_SCHEMA, INDEXED_COLUMNS)

    def __init__(self, db_handle, open_mode, monitor):
        try:
            if not hasattr(db_handle, 'get_table'):
                raise VersionException("Missing Table: " + TABLE_NAME)
            table = db_handle.get_table(TABLE_NAME)
            if table is None or table.schema.version != 0:
                raise VersionException(f"Expected version 0 for table {TABLE_NAME} but got {table.schema.version}")
        except Exception as e:
            print(e)

    def create_markup_item_record(self, markup_item):
        try:
            record = self.table.create_record()
            association = markup_item.association
            manager = association.session
            source_program = manager.source_program
            destination_program = manager.destination_program

            record.set_value(ASSOCIATION_KEY_COL.column(), str(association.key))
            record.set_string(ADDRESS_SOURCE_COL.column(), markup_item.destination_address_source)
            if hasattr(markup_item, 'source_address'):
                address_id = self.get_address_id(source_program, markup_item.source_address)
                record.set_long_value(SOURCE_ADDRESS_COL.column(), address_id)

            destination_address = markup_item.destination_address
            if destination_address is not None:
                address_id = self.get_address_id(destination_program, destination_address)
                record.set_long_value(DESTINATION_ADDRESS_COL.column(), address_id)

            markup_type = VTMarkupTypeFactory.get_id(markup_item.markup_type)
            record.set_short_value(MARKUP_TYPE_COL.column(), markup_type)

            source_value = Stringable.to_string(markup_item.source_value, source_program)
            original_destination_value = Stringable.to_string(markup_item.destination_value, destination_program)
            record.set_string(SOURCE_VALUE_COL.column(), source_value)
            record.set_string(ORIGINAL_DESTINATION_VALUE_COL.column(), original_destination_value)
            status = markup_item.status
            if hasattr(status, 'ordinal'):
                record.set_byte_value(STATUS_COL.column(), int(status.ordinal()))
        except Exception as e:
            print(e)

    def get_address_id(self, program, address):
        try:
            return program.address_map.get_key(address, False)
        except Exception as e:
            print(e)

    def remove_match_markup_item_record(self, key):
        self.table.delete_record(key)

    def get_records(self):
        return self.table.iterator()

    def get_records_by_association_key(self, association_key):
        long_field = LongField(association_key)
        return self.table.index_iterator(ASSOCIATION_KEY_COL.column(), long_field, long_field, True)

    def get_record(self, key):
        return self.table.get_record(key)

    def update_record(self, record):
        self.table.put_record(record)

    def get_record_count(self):
        return self.table.record_count
