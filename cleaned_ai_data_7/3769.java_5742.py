class DataTableModel:
    def __init__(self):
        self.plugin = None
        self.address_map = None
        self.listing = None
        self.addresses = None

    def create_table_column_descriptor(self):
        descriptor = {}
        # Add visible columns here.
        return descriptor

    def reload(self, new_program):
        if new_program is not None:
            self.set_program(new_program)
            self.address_map = AddressMapImpl()
            self.listing = new_program.get_listing()
        else:
            self.address_map = None
            self.listing = None
        # Call the private method to load data.
        self.reload()

    def get_key_count(self):
        if self.listing is not None:
            return len(list(self.listing))
        return 0

    def do_load(self, accumulator, monitor):
        for key in self.get_keys():
            monitor.set_progress(monitor.progress + 1)
            monitor.check_canceled()
            # Check the filter here.
            if self.filter_accepts(key):
                accumulator.add(DataRowObject(key, self.address_map))
        return

    def get_keys(self):
        keys = []
        for data in self.listing:
            keys.append(data.get_min_address())
        return keys

    def filter_accepts(self, key):
        if self.listing is None or self.address_map is None:
            return False
        data = self.listing[data]
        display_name = data.get_data_type().get_display_name()
        if self.addresses is not None:
            return self.plugin.type_enabled(display_name) and self.addresses.contains(data.get_min_address())
        return self.plugin.type_enabled(display_name)

    def add_object(self, row):
        # Add the object to your table here.
        pass

    def remove_object(self, row):
        # Remove the object from your table here.
        pass

    def get_program_selection(self, rows):
        address_set = set()
        for row in rows:
            data_row_object = self.get_row_object(row)
            if data_row_object is not None and data_row_object.address is not None:
                address_set.add(data_row_object.address)
        return ProgramSelection(address_set)

    def get_address(self, row):
        return self.get_row_object(row).address

class DataValueTableColumn:
    def __init__(self):
        pass

    def get_column_name(self):
        return "Data"

    def get_value(self, data_row_object, settings, program, provider):
        if data_row_object is None or data_row_object.address is None:
            return None
        data = self.get_data_for_address(data_row_object)
        if data is not None and data.data_type is not None:
            return str(data.data_type)

    def get_data_for_address(self, data_row_object):
        # Get the data for this address here.
        pass

class TypeTableColumn(DataValueTableColumn):
    def __init__(self):
        super().__init__()

    def get_column_name(self):
        return "Type"

    def get_value(self, data_row_object, settings, program, provider):
        if data_row_object is None or data_row_object.address is None:
            return None
        data = self.get_data_for_address(data_row_object)
        if data is not None and data.data_type is not None:
            return str(data.data_type)

class SizeTableColumn(DataValueTableColumn):
    def __init__(self):
        super().__init__()

    def get_column_name(self):
        return "Size"

    def get_value(self, data_row_object, settings, program, provider):
        if data_row_object is None or data_row_object.address is None:
            return None
        data = self.get_data_for_address(data_row_object)
        if data is not None and data.data_type is not None:
            return str(data.length)

class DataRowObject:
    def __init__(self, address, address_map):
        self.address = address
        self.address_map = address_map

# Define your AddressMapImpl class here.
