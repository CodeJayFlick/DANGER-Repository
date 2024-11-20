class RenameLocalAction:
    def __init__(self):
        self.name = "Rename Variable"
        self.help_location = HelpLocation(HelpTopics.DECOMPILER, "ActionRenameVariable")
        self.popup_menu_data = MenuData(["Rename Variable"], "Decompile")
        self.key_binding_data = KeyBindingData(KeyEvent.VK_L, 0)

    def is_enabled_for_decompiler_context(self, context):
        function = context.get_function()
        if function is None or isinstance(function, UndefinedFunction):
            return False

        token_at_cursor = context.get_token_at_cursor()
        if token_at_cursor is None:
            return False
        if isinstance(token_at_cursor, ClangFieldToken):
            return False

        high_symbol = self.find_high_symbol_from_token(token_at_cursor, context.get_high_function())
        if high_symbol is None:
            return False
        return not high_symbol.is_global()

    def decompiler_action_performed(self, context):
        tool = context.get_tool()
        token_at_cursor = context.get_token_at_cursor()
        high_symbol = self.find_high_symbol_from_token(token_at_cursor, context.get_high_function())

        name_task = RenameVariableTask(tool, context.get_program(), 
            context.get_decompiler_panel(),
            token_at_cursor,
            high_symbol,
            SourceType.USER_DEFINED)

        name_task.run_task(True)


class HelpLocation:
    def __init__(self, topic, description):
        self.topic = topic
        self.description = description


class MenuData:
    def __init__(self, menu_items, popup_name):
        self.menu_items = menu_items
        self.popup_name = popup_name


class KeyBindingData:
    def __init__(self, key_code, modifiers):
        self.key_code = key_code
        self.modifiers = modifiers


# Assuming these classes exist in the same module or are imported from elsewhere.
