class IntelHexExporter:
    def __init__(self):
        self.address_space_option = None
        self.record_size_option = None
        self.default_record_size = 16

    def get_options(self, domain_object_service):
        options_list = []
        domain_object = domain_object_service.get_domain_object()
        if not isinstance(domain_object, Program):
            return None
        program = domain_object
        self.address_space_option = Option("Address Space", program.get_address_factory().get_default_address_space(), AddressSpace)
        if self.record_size_option is None:
            self.record_size_option = RecordSizeOption("Record Size")
        options_list.append(self.address_space_option)
        options_list.append(self.record_size_option)
        return options_list

    def set_options(self, options):
        for option in options:
            if isinstance(option, Option) and option.get_name() == "Address Space":
                self.address_space_option = option
            elif isinstance(option, RecordSizeOption):
                self.record_size_option = option

    class BoundedIntegerVerifier:
        def verify(self, input):
            field = HintTextField(input)
            text = field.get_text()
            try:
                val = int(text)
            except ValueError:
                return False
            return 0 <= val <= 255

    def export(self, file_path, domain_obj, addr_set_view, monitor):
        if not isinstance(domain_obj, Program):
            log.append_msg("Unsupported type: " + str(domain_obj.__class__.__name__))
            return False
        program = domain_obj
        memory = program.get_memory()
        try:
            records = self.dump_memory(program, memory, addr_set_view, monitor)
            with open(file_path, 'w') as writer:
                for record in records:
                    writer.write(record.format() + '\n')
        except MemoryAccessException as e:
            raise ExporterException(e)

    def dump_memory(self, program, memory, addr_set_view, monitor):
        size = self.record_size_option.get_value()
        drop_bytes = self.record_size_option.drop_extra_bytes()
        intel_hex_record_writer = IntelHexRecordWriter(size, drop_bytes)
        set = AddressSet(addr_set_view)
        blocks = memory.get_blocks()
        for block in blocks:
            if not block.is_initialized() or block.get_start().get_address_space() != self.address_space_option.get_value():
                set.delete(AddressRangeImpl(block.get_start(), block.get_end()))
        addresses = set.get_addresses(True)
        while addresses.has_next():
            address = addresses.next()
            byte = memory.get_byte(address)
            intel_hex_record_writer.add_byte(address, byte)
        entry_point = None
        iterator = program.get_symbol_table().get_external_entry_point_iterator()
        while not isinstance(entry_point, Address) and iterator.has_next():
            address = iterator.next()
            if set.contains(address):
                entry_point = address
        return intel_hex_record_writer.finish(entry_point)

    class RecordSizeOption:
        def __init__(self, name="Record Size", value_class=int):
            self.comp = RecordSizeComponent(self.default_record_size)
            super().__init__(name, value_class)

        def get_custom_editor_component(self):
            return self.comp

        def copy(self):
            return RecordSizeOption(name=self.name, value_class=self.value_class, value=self.get_value(), arg="", group="")

        @property
        def value(self):
            return self.comp.get_value()

        @value.setter
        def value(self, val):
            self.comp.set_record_size(val)

        @property
        def drop_extra_bytes(self):
            return self.comp.drop_extra_bytes()

        @drop_extra_bytes.setter
        def drop_extra_bytes(self, val):
            self.comp.set_drop_bytes(val)


class RecordSizeComponent:
    def __init__(self, record_size=16):
        self.input = HintTextField(str(record_size), False)
        self.drop_cb = GCheckBox("Align To Record Size")
        layout = BorderLayout()
        input_panel = JPanel(layout)
        input_panel.add(self.input, BorderLayout.CENTER)
        input_panel.add(self.drop_cb, BorderLayout.EAST)

    @property
    def value(self):
        return int(self.input.get_text())

    @value.setter
    def value(self, val):
        self.input.set_text(str(val))

    @property
    def drop_extra_bytes(self):
        return self.drop_cb.isSelected()

    @drop_extra_bytes.setter
    def drop_extra_bytes(self, val):
        self.drop_cb.setSelected(val)


class HintTextField(JComponent):
    def __init__(self, text="", is_valid=True):
        super().__init__()
        self.text = text
        self.is_field_valid = is_valid

    @property
    def get_text(self):
        return self.text

    @get_text.setter
    def set_text(self, val):
        self.text = str(val)

    @property
    def is_field_valid(self):
        return self.is_field_valid


class GCheckBox(JComponent):
    def __init__(self, text=""):
        super().__init__()
        self.text = text

    @property
    def get_selected(self):
        pass  # Not implemented in Python equivalent of Java code


# Note: The above translation is based on the assumption that you want to keep the same functionality as the original Java code. However, it may not be a direct translation and some modifications might have been necessary.
