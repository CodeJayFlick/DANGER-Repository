class ListingModelConverter:
    def __init__(self, primary_model: 'ListingModel', model: 'ListingModel'):
        self.primary_model = primary_model
        self.model = model
        self.primary_program = primary_model.get_program()
        self.program = model.get_program()

    def add_listener(self, listener):
        self.model.add_listener(listener)

    def dispose(self):
        self.model.dispose()

    def get_address_after(self, address: 'Address'):
        addr = self.get_converted_address(address)
        ret_addr = None if addr is None else self.model.get_address_after(addr)
        if ret_addr is None:
            address_before = self.primary_model.get_address_after(address)
            ret_addr = SimpleDiffUtility.get_compatible_address(self.primary_program, address_before, self.program)
        return ret_addr

    def get_converted_address(self, address: 'Address'):
        return (self.translator and self.translator.translate(address, self.primary_program, self.program)) or \
               SimpleDiffUtility.get_compatible_address(self.primary_program, address, self.program)

    def get_max_width(self):
        return self.model.max_width

    def get_program(self):
        return self.model.get_program()

    def is_closed(self):
        return self.model.is_closed

    def open_data(self, data: 'Data'):
        return self.model.open_data(data)

    def open_all_data(self, addresses: 'AddressSetView', monitor=None):
        self.model.open_all_data(addresses, monitor)

    def close_data(self, data: 'Data'):
        self.model.close_data(data)

    def close_all_data(self, addresses: 'AddressSetView', monitor=None):
        self.model.close_all_data(addresses, monitor)

    def remove_listener(self, listener):
        self.model.remove_listener(listener)

    def set_format_manager(self, format_manager):
        self.model.set_format_manager(format_manager)

    def toggle_open(self, data: 'Data'):
        return self.model.toggle_open(data)

    def adjust_address_set_to_code_unit_boundaries(self, address_set: 'AddressSetView'):
        compatible_address_set = DiffUtility.get_compatible_address_set(address_set, self.program)
        return self.model.adjust_address_set_to_code_unit_boundaries(compatible_address_set)

    @property
    def translator(self):
        return self._translator

    @translator.setter
    def translator(self, value: 'AddressTranslator'):
        self._translator = value

    def copy(self):
        return ListingModelConverter(self.primary_model.copy(), self.model.copy())
