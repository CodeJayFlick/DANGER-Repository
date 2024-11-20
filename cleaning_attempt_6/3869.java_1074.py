import tkinter as tk
from tkinter import simpledialog
from tkinter import messagebox

class StorageTableCellEditor:
    def __init__(self, model):
        self.model = model

    def get_cell_editor_value(self):
        return self.storage

    def is_cell_editable(self, e=None):
        if isinstance(e, int) and e > 1:  # equivalent to ((MouseEvent) e).getClickCount() > 1
            return True
        return False

    def get_table_cell_editor_component(self, table, value, selected, row, column):
        string_value = str(value) if value else ""
        field = tk.Entry(string_value)
        field.configure(background='yellow', state=tk.DISABLED)

        parameter_table_model = table.model()
        row_data = parameter_table_model.get_row_object(row)
        dialog = StorageAddressEditorDialog(self.model.program, self.model.data_type_manager_service,
                                              variable_storage=value, row_data=row_data)

        def show_dialog():
            if not dialog.was_cancelled:
                self.storage = dialog.get_storage()

        table.after(0, lambda: show_dialog())

        return field

class StorageAddressEditorDialog:
    def __init__(self, program, data_type_manager_service, variable_storage, row_data):
        self.program = program
        self.data_type_manager_service = data_type_manager_service
        self.variable_storage = variable_storage
        self.row_data = row_data

    # other methods...

# usage example:

storage_table_cell_editor = StorageTableCellEditor(model)
