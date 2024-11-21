class AutoTableDisassemblerPlugin:
    def __init__(self, tool):
        self.address_table_dialog = None
        self.model = None
        super().__init__()

    def init(self):
        self.create_actions()

    @property
    def program(self):
        return current_program

    def start_dialog(self):
        if not (current_program.get_address_factory().get_default_address_space().size() in [32, 64]):
            Msg.show_warn(None, None, "Cannot search for Address tables on {}-bit memory!".format(current_program.get_address_factory().get_default_address_space().size()))
            return
        if self.address_table_dialog is None:
            self.model = AutoTableDisassemblerModel(self.tool, self)
            self.address_table_dialog = AddressTableDialog(self)
            self.address_table_dialog.set_has_selection(current_selection != null)
        if self.address_table_dialog.is_visible():
            self.address_table_dialog.to_front()
        else:
            self.tool.show_dialog(self.address_table_dialog)

    def dialog_dismissed(self):
        self.address_table_dialog.dispose()
        self.address_table_dialog = None
        if self.model is not None:
            self.model.dispose()
            self.model = None

    # ... and so on for the rest of the methods ...
