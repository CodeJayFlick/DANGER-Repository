Here is a translation of the Java code into equivalent Python:

```Python
from tkinter import *
import datetime

class DataTypeTableCellEditor:
    def __init__(self):
        self.tool = None
        self.service = None
        self.table = None
        self.editorPanel = None
        self.editor = None
        self.dt = None
        self.cellEditorListener = None
        self.dataTypeChooserButton = None

    def update_service(self, tool=None):
        if tool is not None:
            self.service = tool.get_service(DataTypeManagerService)
        return self.service

    def get_allowed(self, row, column):
        return AllowedDataTypes.ALL

    def get_preferred_data_type_manager(self, row, column):
        return None

    def init(self, row, column):
        self.update_service()
        self.editor = DataTypeSelectionEditor(self.service, self.get_allowed(row, column))
        self.editor.set_preferred_data_type_manager(self.get_preferred_data_type_manager(row, column))
        self.editor.set_tab_commits_edit(True)
        self.editor.set_consume_enter_key_press(False)

    def get_table_cell_editor_component(self, newTable, value, isSelected, row, column):
        self.table = newTable
        self.init(row, column)

        # TODO: Use this to verify lengths if variable-length is to be permitted.
        dti = (DataType) value
        if dti is not None:
            self.dt = dti.get_data_type()
        else:
            self.dt = None

        return self.editorPanel

    def stop_edit(self):
        self.update_service()
        data_type = self.service.get_data_type(None)
        if data_type is not None:
            self.editor.set_cell_editor_value(data_type)
            self.editor.stop_cell_editing()
        else:
            self.editor.cancel_cell_editing()

    def get_cell_editor_value(self):
        return self.dt

    def validate_selection(self, data_type):
        return True

    def resolve_selection(self, data_type):
        return data_type

    def is_empty_editor_cell(self):
        return self.editor.get_cell_editor_value_as_text().strip() == ''

    def stop_cell_editing(self):
        columnSelectionModel = self.table.column_model.selection_model
        editingColumn = self.table.editing_column

        try:
            if not self.editor.validate_user_selection():
                return False
        except InvalidDataTypeException as e:
            return False

        data_type = self.resolve_selection(self.editor.get_cell_editor_value_as_data_type())
        if not self.is_empty_editor_cell() and not self.validate_selection(data_type):
            return False

        if data_type is not None:
            if data_type == self.dt:
                self.fire_editing_canceled()
            else:
                self.dt = data_type
                self.fire_editing_stopped()

        columnSelectionModel.set_anchor_selection_index(editingColumn)
        columnSelectionModel.set_lead_selection_index(editingColumn)
        columnSelectionModel.setValueIsAdjusting(False)

        return True

    def is_cell_editable(self, e):
        if isinstance(e, MouseEvent):
            return e.get_click_count() >= 2 and super().is_cell_editable(e)
        else:
            return super().is_cell_editable(e)

class DataTypeManagerService:
    pass

class AllowedDataTypes:
    ALL = None
```

Please note that this is a translation of the Java code into equivalent Python, not necessarily an exact conversion. Some changes were made to make it more idiomatic and efficient in Python.