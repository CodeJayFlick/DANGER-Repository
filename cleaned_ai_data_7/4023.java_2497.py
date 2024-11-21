class ExpandBlockDialog:
    EXPAND_UP = 0
    EXPAND_DOWN = 1

    def __init__(self, tool, model, block, address_factory, dialog_type):
        self.tool = tool
        self.model = model
        self.dialog_type = dialog_type
        super().__init__()

        if dialog_type == ExpandBlockDialog.EXPAND_UP:
            title = "Expand Block Up"
        else:
            title = "Expand Block Down"

        set_help_location(HelpLocation("MEMORY_MAP", title))

        address_factory = af

        model.set_change_listener(self)

        panel = create(block)
        add_work_panel(panel)
        add_ok_button()
        add_cancel_button()

    def ok_callback(self):
        do_expand = lambda: self.execute_model()
        root_panel.set_cursor(Cursor.WAIT_CURSOR)
        SwingUtilities.invokeLater(do_expand)

    def execute_model(self):
        if model.execute():
            close()
        else:
            set_status_text(model.get_message())
            set_ok_enabled(False)

    def create(self, block):
        panel = JPanel(PairLayout(5, 5, 150))
        start_address_input = AddressInput()
        end_address_input = AddressInput()

        start_address_input.set_name("NewStartAddress")
        start_address_input.set_address_factory(address_factory)
        start_address_input.set_address(block.get_start())
        start_address_input.set_address_space_editable(False)

        end_address_input.set_name("EndAddress")
        end_address_input.set_address_factory(address_factory)
        end_address_input.set_address(block.get_end())
        end_address_input.set_address_space_editable(False)

        if self.dialog_type == ExpandBlockDialog.EXPAND_UP:
            start_field = JTextField(10, True)
            start_field.set_name("StartAddress")
            start_field.set_text(str(block.get_start()))
            panel.add(GLabel("New Start Address:", SwingConstants.RIGHT))
            panel.add(start_address_input)
        else:
            end_field = JTextField(10, True)
            end_field.set_name("EndAddress")
            end_field.set_text(str(block.get_end()))
            panel.add(GLabel("Start Address:", SwingConstants.RIGHT))
            panel.add(end_address_input)

        length_field = RegisterField(32, None, False)
        length_field.set_name("BlockLength")
        length_field.set_value(Long.valueOf(model.get_length()))

        panel.add(GLabel("Block Length:", SwingConstants.RIGHT))
        panel.add(length_field)

    def add_listeners(self):
        start_address_input.add_change_listener(AddressChangeListener())
        end_address_input.add_change_listener(AddressChangeListener())
        length_field.add_change_listener(LengthChangeListener())

        al = ActionListener(lambda e: self.status_text_set(""))
        start_field.addActionListener(al)
        end_field.addActionListener(al)
        length_field.addActionListener(al)

    class LengthChangeListener:
        def state_changed(self, event):
            if is_changing():
                return
            status_text_set("")
            length_changed()

        def length_changed(self):
            length = 0
            val = length_field.get_value()
            if val == None:
                set_ok_enabled(False)
            else:
                length = val.long_value

    class AddressChangeListener:
        def state_changed(self, event):
            if is_changing():
                return
            status_text_set("")
            address_changed()

        def address_changed(self):
            if self.dialog_type == ExpandBlockDialog.EXPAND_UP:
                start_addr = start_address_input.get_address()
                if start_addr == None:
                    if start_address_input.has_input():
                        status_text_set("Invalid Address")
                    set_ok_enabled(False)
                else:
                    model.set_start_address(start_addr)

    def state_changed(self, event):
        message = self.model.get_message()
        status_text_set(message)
        set_ok_enabled(len(message) == 0)
        length_field.set_value(Long.valueOf(model.get_length()))
        start_addr = model.get_start_address()
        end_addr = model.get_end_address()

        is_changing = True
        if self.dialog_type == ExpandBlockDialog.EXPAND_UP and start_addr != None:
            start_address_input.set_address(start_addr)

    def close(self):
        pass

class HelpLocation:
    def __init__(self, topic, title):
        self.topic = topic
        self.title = title

    def get_topic(self):
        return self.topic

    def get_title(self):
        return self.title

class AddressInput:
    def __init__(self):
        super().__init__()

    def set_name(self, name):
        pass

    def set_address_factory(self, address_factory):
        pass

    def set_address_space_editable(self, editable):
        pass

    def get_address(self):
        return None

    def has_input(self):
        return False
