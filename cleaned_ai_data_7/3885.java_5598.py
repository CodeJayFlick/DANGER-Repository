class RevertThunkFunctionAction:
    def __init__(self, plugin):
        self.func_plugin = plugin
        super().__init__("Revert Thunk Function", plugin.name)

        # top-level item usable only on a function
        menu_data = MenuData(["FunctionPlugin.FUNCTION_MENU_PULLRIGHT", "Revert Thunk Function..."], None,
                              "FunctionPlugin.THUNK_FUNCTION_MENU_SUBGROUP")
        self.set_popup_menu_data(menu_data)
        
        help_location = HelpLocation("FunctionPlugin", "ThunkFunctions")
        self.set_help_location(help_location)

        # set enabled to True
        self.enabled = True

    def actionPerformed(self, context):
        program = context.get_program()
        function_mgr = program.get_function_manager()

        if isinstance(context, ListingActionContext):
            func = function_mgr.get_function_at(context.address)
        elif isinstance(context, ProgramSymbolActionContext):
            symbol_context = context
            s = symbol_context.get_first_symbol()
            if s is None or not isinstance(s, Function):
                return

            func = s.object
        else:
            raise Exception("Invalid context for action")

        if func is None or not func.is_thunk():
            return

        response = OptionDialog.show_yes_no_dialog(func_plugin.tool.active_window,
                                                     "Revert Thunk Confirmation",
                                                     f"Do you wish to revert function '{func.name}' "
                                                     f"to a non-thunk Function?")

        if response != OptionDialog.YES_OPTION:
            return

        tx_id = program.start_transaction("Revert Thunk")
        try:
            func.set_thunked_function(None)
        finally:
            program.end_transaction(tx_id, True)

    def is_enabled_for_context(self, context):
        program = context.get_program()
        if program is None:
            return False

        function_mgr = program.get_function_manager()

        if isinstance(context, ListingActionContext):
            func = function_mgr.get_function_at(context.address)
        elif isinstance(context, ProgramSymbolActionContext):
            symbol_context = context
            s = symbol_context.get_first_symbol()
            if s is None or not isinstance(s, Function) or symbol_context.symbol_count != 1:
                return False

            func = s.object
        else:
            return False

        return func is not None and func.is_thunk()

class MenuData:
    def __init__(self, items=None, parent_menu_data=None, subgroup=""):
        self.items = items if items is not None else []
        self.parent_menu_data = parent_menu_data
        self.subgroup = subgroup

class HelpLocation:
    def __init__(self, topic, subtopic):
        self.topic = topic
        self.subtopic = subtopic

class FunctionPlugin:
    FUNCTION_MENU_PULLRIGHT = "FunctionMenuPullRight"
    THUNK_FUNCTION_MENU_SUBGROUP = "ThunkFunctions"

    def get_tool(self):
        pass  # Implement this method to return the tool object.

class OptionDialog:
    YES_OPTION = True
    NO_OPTION = False

    @staticmethod
    def show_yes_no_dialog(parent, title, message):
        raise Exception("Implement this method in your subclass.")

# Example usage:

func_plugin = FunctionPlugin()
action = RevertThunkFunctionAction(func_plugin)
