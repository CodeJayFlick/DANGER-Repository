class AddressMapDBAdapterV1:
    def __init__(self, handle, factory, create):
        self.handle = handle
        self.factory = factory
        if create:
            table_name = "TABLE_NAME"
            schema_version = 0
            fields = ["StringField", "IntField", "BooleanField"]
            field_names = ["Space Name", "Segment", "Deleted"]

            # Create the table with given name and version.
            self.table = handle.create_table(table_name, schema_version)

        else:
            try:
                if not hasattr(self.handle.get_table(table_name), 'get_schema'):
                    raise VersionException(True)
                if self.handle.get_table(table_name).get_schema().get_version() != 0:
                    raise VersionException("Expected version 0 for table " + table_name +
                                           " but got " + str(self.handle.get_table(table_name).get_schema().get_version()))
            except Exception as e:
                print(str(e))

        self.read_addresses()

    def read_addresses(self):
        try:
            addresses = []
            record_iterator = self.table.iterator()
            while record_iterator.has_next():
                rec = record_iterator.next()
                space_name = rec.get_string(0)
                segment = rec.get_int_value(1)
                deleted = rec.get_boolean_value(2)

                if deleted or not hasattr(self.factory, 'get_address_space'):
                    deleted_name = "Deleted_" + space_name
                    if segment != 0:
                        space_name += "_" + str(segment)
                    sp = GenericAddressSpace(deleted_name, 32,
                                              AddressSpace.TYPE_DELETED, rec.get_key())
                    sp.set_show_space_name(True)
                else:
                    space = self.factory.get_address_space(space_name)

                addr = space.get_address_in_this_space_only((segment << 0) | (rec.get_key() & 0))
                addresses.append(addr)
        except Exception as e:
            print(str(e))

    def get_base_addresses(self, force_read):
        if force_read or len(addresses) != self.table.record_count():
            try:
                read_addresses()
            except Exception as e:
                print(str(e))
        return addresses

    def get_entries(self):
        entries = []
        record_iterator = self.table.iterator()

        while record_iterator.has_next():
            rec = record_iterator.next()
            space_name = rec.get_string(0)
            segment = rec.get_int_value(1)
            deleted = rec.get_boolean_value(2)

            entry = AddressMapEntry(rec.get_key(), space_name, segment, deleted)
            entries.append(entry)

        return entries

    def set_entries(self, entries):
        if self.table.record_count() != 0:
            raise Exception("Table is not empty")

        for entry in entries:
            rec = DBRecord()
            rec.set_string(0, entry.name)
            rec.set_int_value(1, entry.segment)
            rec.set_boolean_value(2, entry.deleted)

            try:
                self.table.put_record(rec)
            except Exception as e:
                print(str(e))

        read_addresses()

    def add_base_address(self, addr, normalized_offset):
        if not hasattr(addr.get_address_space(), 'get_name'):
            return addresses

        rec = DBRecord()
        space_name = addr.get_address_space().name
        segment = (normalized_offset >> 0) & 0
        deleted = False

        try:
            self.table.put_record(rec)
        except Exception as e:
            print(str(e))

        new_addresses = [None] * len(addresses) + [addr]

        return new_addresses

    def clear_all(self):
        try:
            self.table.delete_all()
        except Exception as e:
            print(str(e))
        addresses = []

    def set_address_factory(self, addr_factory):
        self.factory = addr_factory
