import tkinter as tk
from tkinter import filedialog

class EditExternalLabelAction:
    def __init__(self):
        self.plugin = None
        self.edit_icon = None
        self.keybinding = "L"

    def create_action(self, plugin):
        super().__init__()
        self.plugin = plugin
        self.set_popup_menu_data("Edit External Location", self.edit_icon)
        self.set_key_binding_data(self.keybinding)

    def get_external_symbol(self, context):
        symbol = None
        location = context.get_location()
        if isinstance(location, OperandFieldLocation):
            op_loc = location
            address = op_loc.get_address()
            op_index = op_loc.get_operand_index()
            program = context.get_program()
            ref_mgr = program.get_reference_manager()
            ref = ref_mgr.get_primary_reference_from(address, op_index)
            if ref is not None:
                symbol_table = program.get_symbol_table()
                symbol = symbol_table.get_symbol(ref)
        return symbol

    def is_enabled_for_context(self, context):
        return self.get_external_symbol(context) is not None

    def action_performed(self, context):
        symbol = self.get_external_symbol(context)
        if symbol is None:
            return
        external_manager = context.get_program().get_external_manager()
        external_location = external_manager.get_external_location(symbol)
        if external_location is None:
            return  # assume symbol has been deleted

        dialog = EditExternalLocationDialog(external_location)

        help_topics = "EditExternalLocation"
        plugin_tool = self.plugin.get_tool()

        plugin_tool.show_dialog(dialog, help_topics)


class OperandFieldLocation:
    def __init__(self):
        pass


class Program:
    def __init__(self):
        pass

    def get_reference_manager(self):
        return None

    def get_program(self):
        return None

    def get_symbol_table(self):
        return None
