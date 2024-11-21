class EmptyListingModel:
    def add_listener(self, listener):
        # stub

    def get_address_after(self, address):
        return None

    def get_address_before(self, address):
        return None

    def get_address_set(self):
        return AddressSet()

    def get_layout(self, address, is_gap_address):
        return None

    def get_max_width(self):
        return 0

    def get_program(self):
        return None

    def is_open(self, object):
        return False

    def remove_listener(self, listener):
        # stub

    def toggle_open(self, object):
        # stub

    def open_all_data(self, data, monitor=None):
        # stub

    def close_all_data(self, data, monitor=None):
        # stub

    def close_data(self, data):
        # stub

    def is_opened(self):
        return False

    def set_format_manager(self, format_manager):
        # stub

    def dispose(self):
        # stub

    def adjust_address_set_to_code_unit_boundaries(self, address_set):
        return AddressSet()

    def copy(self):
        return EmptyListingModel()
