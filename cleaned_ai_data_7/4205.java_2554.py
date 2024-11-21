class RegisterValuesPanel:
    def __init__(self, tool, provider):
        self.tool = tool
        self.provider = provider
        self.setLayout(QVBoxLayout())
        self.table = create_basic_table()
        self.add(self.create_scrollable_area(), BorderLayout.CENTER)
        self.table.setSelectionMode(Qt.SelectionMode.MultiRangeSelection)

    def edit_row(self, row):
        range = self.model.values[row]
        start = range.get_start_address()
        end = range.get_end_address()
        value = range.get_value()
        dialog = EditRegisterValueDialog(self.selected_register, start, end, value)
        self.tool.show_dialog(dialog, self)

    def update_value(self, start, end, new_start, new_end, new_value):
        cmd = CompoundCmd("Update Register Range")
        cmd1 = SetRegisterCmd(self.selected_register, start, end, None)
        cmd2 = SetRegisterCmd(self.selected_register, new_start, new_end, new_value)
        cmd.add(cmd1)
        cmd.add(cmd2)
        self.tool.execute(cmd, self.current_program)

    def create_basic_table(self):
        model = RegisterValuesTableModel()
        table = GhidraTable(model)
        table.setSelectionMode(Qt.SelectionMode.MultiRangeSelection)
        return table

    # ... other methods ...

class EditRegisterValueDialog(QDialog):
    def __init__(self, register, start_address, end_address, value):
        super().__init__()
        self.register = register
        self.start_address = start_address
        self.end_address = end_address
        self.value = value

    # ... method implementations ...
