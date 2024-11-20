Here is the translation of the Java code into equivalent Python:

```Python
class RetypeReturnAction:
    def __init__(self):
        self.name = "Retype Return"
        self.help_location = HelpLocation(HelpTopics.DECOMPILER, "ActionRetypeReturn")
        self.popup_menu_data = MenuData(["Retype Return"], "Decompile")
        self.key_binding_data = KeyBindingData(KeyEvent.VK_L, InputEvent.CTRL_DOWN_MASK)

    def is_enabled_for_decompiler_context(self, context):
        function = context.get_function()
        if not (function and isinstance(function, Function)):
            return False
        token_at_cursor = context.get_token_at_cursor()
        return isinstance(token_at_cursor.parent(), ClangReturnType)

    def decompiler_action_performed(self, context):
        program = context.get_program()
        tool = context.get_tool()
        token_at_cursor = context.get_token_at_cursor()
        high_function = context.get_high_function()
        function = high_function.get_function()
        data_type_manager = program.data_type_manager

        parent = token_at_cursor.parent()
        if not isinstance(parent, ClangReturnType):
            return
        data_type = self.choose_data_type(tool, program, parent.get_data_type())
        if not data_type:
            return
        commit_required = self.check_full_commit(None, high_function)
        if commit_required:
            response = OptionDialog.show_option_dialog(
                tool.get_tool_frame(),
                "Parameter Commit Required",
                f"Retyping the return value requires all other parameters to be committed! Continue with retype?",
                "Continue"
            )
            if response != OptionDialog.OPTION_ONE:
                return

        successful_mod = False
        transaction_id = program.start_transaction("Retype return type")
        try:
            function.set_return_type(data_type, SourceType.USER_DEFINED)
            successful_mod = True
        except InvalidInputException as e:
            Msg.show_error(self, tool.get_tool_frame(), "Retype Failed", f"Failed to re-type return type '{self.name}': {e.message}")
        finally:
            program.end_transaction(transaction_id, successful_mod)

    def choose_data_type(self, tool, program, data_type):
        # Implement this method
        pass

    def check_full_commit(self, _, high_function):
        # Implement this method
        return False


class HelpLocation:
    def __init__(self, topic, name):
        self.topic = topic
        self.name = name


class MenuData:
    def __init__(self, items, label):
        self.items = items
        self.label = label


class KeyBindingData:
    def __init__(self, key_event, input_event_mask):
        self.key_event = key_event
        self.input_event_mask = input_event_mask


class OptionDialog:
    OPTION_ONE = 1

    @staticmethod
    def show_option_dialog(frame, title, message, label):
        # Implement this method
        pass


class Msg:
    @staticmethod
    def show_error(self, frame, title, message):
        # Implement this method
        pass


# You need to implement the following methods:
# - choose_data_type in RetypeReturnAction class
# - check_full_commit in RetypeReturnAction class
# - OptionDialog.show_option_dialog and Msg.show_error in their respective classes

```

This translation maintains the same structure as the original Java code, but it is written entirely in Python.