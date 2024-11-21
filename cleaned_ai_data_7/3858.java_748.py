class EditOperandNameAction:
    def __init__(self, function_plugin):
        self.function_plugin = function_plugin
        super().__init__("Rename Function Variable", function_plugin.get_name())

        menu_data = MenuData(["Rename Variable...", "Edit Failed"], None)
        set_popup_menu_data(menu_data)

        key_binding_data = KeyBindingData(KeyEvent.VK_L, 0)
        set_key_binding(key_binding_data)

    def actionPerformed(self, context):
        if self.is_enabled():
            variable = self.get_variable(context)
            if variable is not None:
                symbol = variable.get_symbol()
                if symbol is None:
                    print("Edit Failed: Variable may not be modified")
                    return
                dialog = AddEditDialog("Edit Variable Name", function_plugin.get_tool())
                dialog.edit_label(symbol, context.get_program())

    def get_variable(self, context):
        if context.has_selection() or context.get_address() is None:
            return None

        location = context.get_location()
        program = context.get_program()

        if not isinstance(location, OperandFieldLocation):
            return None
        oloc = location  # assuming this line does the same thing as in Java code
        inst = program.get_listing().get_instruction_at(oloc.get_address())
        if inst is not None:
            variable_offset = oloc.get_variable_offset()
            if variable_offset is not None:
                return variable_offset.get_variable()

    def is_enabled_for_context(self, context):
        v = self.get_variable(context)
        return v is not None and v.get_symbol() is not None
