class ProgramBigListingModel:
    def __init__(self, program: 'Program', format_manager):
        self.program = program
        self.listing = program.get_listing()
        self.format_manager = format_manager
        self.dummy_factory = DummyFieldFactory(format_manager)
        self.open_close_mgr = OpenCloseManager()
        self.field_options = format_manager.get_field_options()

    def options_changed(self, tool_options: 'ToolOptions', option_name: str, old_value: object, new_value: object):
        if option_name == DISPLAY_EXTERNAL_FUNCTION_POINTER_OPTION_NAME:
            show_external_function_pointer_format = bool(new_value)
            self.format_model_changed(None)
        elif option_name == DISPLAY_NONEXTERNAL_FUNCTION_POINTER_OPTION_NAME:
            show_nonexternal_function_pointer_format = bool(new_value)
            self.format_model_changed(None)

    def get_address_set(self):
        return self.program.get_memory()

    def dispose(self):
        self.program.remove_listener(self)
        self.field_options.remove_options_change_listener(self)
        self.format_manager.remove_format_model_listener(self)
        self.listeners.clear()

    def set_format_manager(self, format_manager: 'FormatManager'):
        self.format_manager = format_manager
        self.format_manager.add_format_model_listener(self)

    def state_changed(self, event):
        self.notify_data_changed(True)

    def get_layout(self, address: Address, is_gap_address: bool) -> Layout:
        layout = self.layout_cache.get(address, is_gap_address)
        if layout is None:
            layout = self.do_get_layout(address, is_gap_address)
            self.layout_cache.put(address, layout, is_gap_address)
        return layout

    def do_get_layout(self, address: Address, is_gap_address: bool) -> Layout:
        list_ = []
        field_format_model = None
        code_unit = self.listing.get_code_unit_at(address)
        if isinstance(code_unit, Data):
            data = code_unit
            if data.num_components > 0:
                if self.open_close_mgr.is_open(data.min_address()):
                    address_proxy = AddressProxy(self, address)
                    list_.append(RowLayout([address_proxy], index_size=1))
        else:
            cu = self.listing.get_code_unit_after(address)
            return cu.min_address() if cu is None else cu.min_address()

    def get_pointer_referenced_function(self, data: Data) -> Function:
        reference = data.primary_reference(0)
        if reference is not None and (reference.is_external_reference or show_nonexternal_function_pointer_format):
            return self.listing.get_function_at(reference.to_address)

    # ... other methods ...
