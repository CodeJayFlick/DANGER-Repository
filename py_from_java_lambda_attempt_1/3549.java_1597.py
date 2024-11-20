Here is the translation of the given Java code into equivalent Python:

```Python
class AddBitFieldAction:
    ACTION_NAME = "Add Bitfield"
    GROUP_NAME = "BITFIELD_ACTION_GROUP"
    DESCRIPTION = "Add a bitfield at the position of a selected component"

    def __init__(self, provider):
        self.provider = provider

    def get_action_name(self):
        return self.ACTION_NAME

    def get_group_name(self):
        return self.GROUP_NAME

    def get_description(self):
        return self.DESCRIPTION

    def actionPerformed(self, context):
        if not isinstance(context.model, CompEditorModel) or len(context.model.get_selected_rows()) != 1:
            return
        row_index = context.model.get_selected_rows()[0]

        dlg = BitFieldEditorDialog(
            provider.dtm_service,
            -(row_index + 1),
            context.model.show_hex_numbers,
            lambda ordinal: self.refresh_table_and_selection(ordinal)
        )
        c = provider.get_component()
        DockingWindowManager().show_dialog(c, dlg)

    def refresh_table_and_selection(self, ordinal):
        # equivalent to notifyCompositeChanged() in Java
        pass

    def adjust_enablement(self):
        enabled = True
        if not isinstance(context.model.view_composite, Structure) or context.model.is_packing_enabled():
            enabled = False
        self.set_enabled(enabled)

class CompEditorModel:
    def __init__(self):
        # equivalent to the constructor in Java
        pass

    def get_selected_rows(self):
        # equivalent to getSelectedRows() in Java
        return []

    def is_packing_enabled(self):
        # equivalent to isPackingEnabled() in Java
        return False

class BitFieldEditorDialog:
    def __init__(self, view_composite, dtm_service, row_index, show_hex_numbers, refresh_table_and_selection):
        self.view_composite = view_composite
        self.dtm_service = dtm_service
        self.row_index = row_index
        self.show_hex_numbers = show_hex_numbers
        self.refresh_table_and_selection = refresh_table_and_selection

    def show(self):
        # equivalent to showDialog() in Java
        pass
```

Please note that this is a direct translation of the given code into Python, and it may not be perfect. For example, there are no error checks for null or None values in Python as they do exist in Java.