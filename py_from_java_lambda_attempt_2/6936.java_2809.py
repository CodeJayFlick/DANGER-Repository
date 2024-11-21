Here is a translation of the Java code into equivalent Python:

```Python
class RetypeGlobalAction:
    def __init__(self):
        self.name = "Retype Global"
        self.help_location = HelpLocation(HelpTopics.DECOMPILER, "ActionRetypeGlobal")
        self.popup_menu_data = MenuData(["Retype Global"], "Decompile")
        self.key_binding_data = KeyBindingData(KeyEvent.VK_L, InputEvent.CTRL_DOWN_MASK)

    def is_enabled_for_decompiler_context(self, context):
        function = context.get_function()
        if not (function and isinstance(function, Function)):
            return False

        token_at_cursor = context.get_token_at_cursor()
        if not (token_at_cursor and isinstance(token_at_cursor, ClangToken) and
                not isinstance(token_at_cursor, ClangFieldToken) and
                not isinstance(token_at_cursor.Parent(), ClangReturnType) and
                token_at_cursor.is_variable_ref()):
            return False

        high_symbol = self.find_high_symbol_from_token(token_at_cursor, context.get_high_function())
        if not (high_symbol and isinstance(high_symbol, HighSymbol)):
            return False

        return high_symbol.is_global()

    def decompiler_action_performed(self, context):
        program = context.get_program()
        tool = context.get_tool()
        token_at_cursor = context.get_token_at_cursor()

        data_type = None
        high_symbol = self.find_high_symbol_from_token(token_at_cursor, context.get_high_function())
        if not (high_symbol and isinstance(high_symbol, HighSymbol)):
            return

        data_type = self.choose_data_type(tool, program, high_symbol.get_data_type())

        if not (data_type):
            return

        try:
            transaction = program.start_transaction("Retype Global")
            if data_type.get_data_type_manager() != program.get_data_type_manager():
                data_type = program.get_data_type_manager().resolve(data_type, None)
            HighFunctionDBUtil.update_db_variable(high_symbol, None, data_type,
                    SourceType.USER_DEFINED)
        except (DuplicateNameException, InvalidInputException) as e:
            Msg.show_error(self, tool.get_tool_frame(), "Retype Failed",
                    f"Failed to re-type variable '{high_symbol.name}': {e.message}")
        finally:
            program.end_transaction(transaction)

    def find_high_symbol_from_token(self, token_at_cursor, high_function):
        # This method is not implemented in the original Java code
        pass

    def choose_data_type(self, tool, program, data_type):
        # This method is not implemented in the original Java code
        pass


class HelpLocation:
    def __init__(self, topic, help_topic):
        self.topic = topic
        self.help_topic = help_topic


class MenuData:
    def __init__(self, menu_items, popup_name):
        self.menu_items = menu_items
        self.popup_name = popup_name


class KeyBindingData:
    def __init__(self, key_code, modifier_mask):
        self.key_code = key_code
        self.modifier_mask = modifier_mask


# This class is not implemented in the original Java code
class ClangToken:
    pass

# This class is not implemented in the original Java code
class Function:
    pass

# This class is not implemented in the original Java code
class HighSymbol:
    def __init__(self, name):
        self.name = name

    def get_data_type(self):
        # This method is not implemented in the original Java code
        pass

    def is_global(self):
        # This method is not implemented in the original Java code
        pass


# This class is not implemented in the original Java code
class DataType:
    pass

# This class is not implemented in the original Java code
class PluginTool:
    pass

# This class is not implemented in the original Java code
class Program:
    def __init__(self):
        self.data_type_manager = None

    def get_data_type_manager(self):
        return self.data_type_manager

    def start_transaction(self, transaction_name):
        # This method is not implemented in the original Java code
        pass

    def end_transaction(self, transaction_id, successful_modification=False):
        # This method is not implemented in the original Java code
        pass


# This class is not implemented in the original Java code
class Msg:
    @staticmethod
    def show_error(action, tool_frame, error_title, error_message):
        print(f"Error: {error_title} - {error_message}")
```

Please note that this translation does not include all classes and methods from the original Java code. The `ClangToken`, `Function`, `HighSymbol`, `DataType`, `PluginTool`, and `Program` classes are not implemented in Python, as they were not provided with their respective implementations in the original Java code.