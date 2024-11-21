class EditRegisterValueDialog:
    def __init__(self, register, start, end, value):
        self.start_addr_field = None
        self.end_addr_field = None
        self.register_value_field = None
        self.was_cancelled = True

        super().__init__("Edit Register Value Range")
        work_panel = self.build_work_panel(register, start, end, value)
        self.add_work_panel(work_panel)

        self.add_ok_button()
        self.add_cancel_button()
        self.set_help_location("RegisterPlugin", "EditRegisterValues")

    def build_work_panel(self, register, start, end, value):
        panel = JPanel(5, 1)  # This is a custom class

        register_field = JTextField(f"{register.name} ({register.bit_length})")
        register_field.setEditable(False)

        self.start_addr_field = AddressInput()
        self.end_addr_field = AddressInput()

        change_listener = ChangeListener()  # This is a custom class
        def update_ok(event):
            self.update_ok()
        start_addr_field.add_change_listener(update_ok)
        end_addr_field.add_change_listener(update_ok)

        register_value_field = FixedBitSizeValueField(register.bit_length, True, False)  # These are custom classes

        panel.border = BorderFactory.create_empty_border(10, 10, 10, 10)
        panel.add(GLabel("Register:"))
        panel.add(register_field)
        panel.add(GLabel("Start Address:"))
        panel.add(self.start_addr_field)
        panel.add(GLabel("End Address:"))
        panel.add(self.end_addr_field)
        panel.add(GLabel("Value:"))
        panel.add(register_value_field)

        return panel

    def update_ok(self):
        start = self.start_addr_field.get_address()
        end = self.end_addr_field.get_address()

        if not check_valid_addresses(start, end):  # This is a custom function
            set_status_text("Invalid addresses", MessageType.ERROR)
            return False
        else:
            return True

    def add_ok_button(self):
        pass  # You need to implement this method in Python

    def add_cancel_button(self):
        pass  # You need to implement this method in Python

    def check_valid_addresses(self, start_space, start, end_space, end):
        if start_space != end_space:
            set_status_text("Start and end addresses must be in the same address space!", MessageType.ERROR)
            return False
        elif start is None or end is None:
            set_status_text(f"Please enter a starting ({start}) and an ending ({end}) address.", MessageType.ERROR)
            return False
        else:
            if start.get_address_space() != start_space:
                # must be an overlay that is not in the range
                set_status_text("Start offset must be in overlay range [" + str(start_space.min_address) + ", " + str(start_space.max_address) + "]",
                                MessageType.ERROR)
                return False
            elif end.get_address_space() != end_space:
                # must be an overlay that is not in the range
                set_status_text("End offset must be in overlay range [" + str(end_space.min_address) + ", " + str(end_space.max_address) + "]",
                                MessageType.ERROR)
                return False
            elif start > end:
                set_status_text("Start address must be less than end address!", MessageType.ERROR)
                return False

        return True

    def close(self):
        pass  # You need to implement this method in Python

    @property
    def was_cancelled(self):
        return self.was_cancelled

    @property
    def start_address(self):
        return self.start_addr_field.get_address()

    @property
    def end_address(self):
        return self.end_addr_field.get_address()

    @property
    def value(self):
        return self.register_value_field.value
