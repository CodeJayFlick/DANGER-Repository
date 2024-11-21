class AddVarArgsAction:
    def __init__(self, function_plugin):
        self.function_plugin = function_plugin
        super().__init__("Add Var Args", function_plugin.get_name())
        self.update_popup_menu(True)

        # set help location
        self.set_help_location("FunctionPlugin", "Add_Var_Args")

    def update_popup_menu(self, is_signature_action):
        if is_signature_action:
            popup_data = MenuData([["FUNCTION_MENU_PULLRIGHT", "Add Var Args"], None], FunctionPlugin.FUNCTION_MENU_SUBGROUP)
        else:
            popup_data = MenuData([["VARIABLE_MENU_PULLRIGHT", "Add Var Args"], None], FunctionPlugin.VARIABLE_MENU_SUBGROUP)

    def actionPerformed(self, context):
        loc = context.get_location()

        if isinstance(loc, (FunctionSignatureFieldLocation, VariableLocation)):
            function = self.function_plugin.get_function(context)
            if function and not function.has_var_args():
                command = SetFunctionVarArgsCommand(function, True)
                tool = self.function_plugin.get_tool()
                program = context.get_program()

                if not tool.execute(command, program):
                    tool.set_status_info(f"Unable to add function var Args on {function.name}")

    def is_enabled_for_context(self, context):
        if context.has_selection():
            return False

        loc = context.get_location()
        if isinstance(loc, (VariableLocation, FunctionSignatureFieldLocation)):
            self.update_popup_menu(isinstance(loc, FunctionSignatureFieldLocation))
        else:
            self.update_popup_menu(False)

        function = self.function_plugin.get_function(context)
        return function and not function.has_var_args()

class MenuData(list):
    def __init__(self, items=None, subgroup=None):
        super().__init__()
        if items is None:
            items = []
        for item in items:
            self.append(item)
