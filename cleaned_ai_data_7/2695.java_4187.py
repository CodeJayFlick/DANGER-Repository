class HexBigIntegerTableCellEditor:
    def __init__(self):
        self.input = None

    def get_cell_editor_value(self):
        return self.input.value if self.input else None

    def is_cell_editable(self, e):
        if isinstance(e, MouseEvent) and e.click_count >= 2:
            return super().is_cell_editable(e)
        return super().is_cell_editable(e)

    def get_table_cell_editor_component(self, table, value, selected, row, column):
        self.input = IntegerTextField()
        self.input.component.border = UIManager.get_border("Table.focusCellHighlightBorder")
        self.input.allow_negative_values = True
        self.input.hex_mode = True
        self.input.allows_hex_prefix = False
        self.input.show_number_mode = True

        if value is not None:
            self.input.value = value
            CellEditorUtils.on_one_focus(self.input.component, lambda: self.input.select_all())
        self.input.add_listener(lambda e: self.stop_cell_editing())

        return self.input.component


class IntegerTextField:
    def __init__(self):
        pass

    @property
    def component(self):
        # This should be replaced with actual GUI code in Python.
        pass

    @property
    def value(self):
        # This should be replaced with actual GUI code in Python.
        pass

    @value.setter
    def value(self, val):
        # This should be replaced with actual GUI code in Python.
        pass


class CellEditorUtils:
    @staticmethod
    def on_one_focus(component, func):
        # This should be replaced with actual GUI code in Python.
        pass


# Usage example:

editor = HexBigIntegerTableCellEditor()
