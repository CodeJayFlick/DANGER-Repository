class EditFunctionAction:
    def __init__(self, function_plugin):
        self.function_plugin = function_plugin
        super().__init__("Edit Function", function_plugin.get_name())

        menu_data = MenuData(["Edit Function..."], None,
                              function_plugin.FUNCTION_MENU_SUBGROUP,
                              MenuData.NO_MNEMONIC,
                              function_plugin.FUNCTION_SUBGROUP_BEGINNING)
        key_binding_data = KeyBindingData(KeyEvent.VK_F, 0)

        self.set_popup_menu_data(menu_data)
        self.set_key_binding_data(key_binding_data)

        help_location = HelpLocation("FunctionPlugin", "Edit_Function")
        self.set_help_location(help_location)

    def action_performed(self, context):
        function = None
        if isinstance(context, ListingActionContext):
            listing_context = context
            location = listing_context.get_location()
            if isinstance(location, FunctionLocation):
                function = self.function_plugin.get_function(listing_context)
            elif isinstance(location, OperandFieldLocation):
                function = self.function_plugin.get_function_in_operand_field(
                    context.get_program(), location)

        else:
            symbol_context = context
            symbol = symbol_context.get_first_symbol()
            if symbol is None:
                return  # assume symbol removed

            function = symbol.get_object() if isinstance(symbol, Function) else None

        if function is not None:
            tool = self.function_plugin.get_tool()
            service = tool.get_service(DataTypeManagerService)
            dialog = FunctionEditorDialog(service, function)
            tool.show_dialog(dialog, context.get_component_provider())

    def is_enabled_for_context(self, context):
        if isinstance(context, ListingActionContext):
            listing_context = context
            has_selection = listing_context.has_selection()
            address = listing_context.get_address()

            location = listing_context.get_location()
            if (isinstance(location, FunctionLocation) or
                    (isinstance(location, OperandFieldLocation) and self.function_plugin.
                       get_function_in_operand_field(context.get_program(), location))):
                return True

        elif isinstance(context, ProgramSymbolActionContext):
            symbol_context = context
            count = symbol_context.get_symbol_count()

            if count == 1:
                s = symbol_context.get_first_symbol()
                if s is not None and isinstance(s, Function):
                    function = s.get_object() if isinstance(s, Function) else None

                    return True

        return False


class ProgramActionContext:
    pass
