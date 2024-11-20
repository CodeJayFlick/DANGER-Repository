Here is the translation of the Java code into Python:

```Python
class DeleteVarArgsAction:
    def __init__(self, function_plugin):
        self.function_plugin = function_plugin
        super().__init__("Delete VarArgs", function_plugin.get_name())
        update_popup_menu(True)

    def update_popup_menu(self, is_signature_action):
        if is_signature_action:
            popup_data = MenuData([FunctionPlugin.FUNCTION_MENU_PULL_RIGHT, "Delete VarArgs"], None, FunctionPlugin.FUNCTION_MENU_SUBGROUP)
        else:
            popup_data = MenuData([FunctionPlugin.VARIABLE_MENU_PULL_RIGHT, "Delete VarArgs"], None, FunctionPlugin.VARIABLE_MENU_SUBGROUP)

    def actionPerformed(self, context):
        function = self.function_plugin.get_function(context)
        if function is not None and function.has_var_args():
            command = SetFunctionVarArgsCommand(function, False)
            tool = self.function_plugin.get_tool()
            program = context.get_program()

            if not tool.execute(command, program):
                tool.set_status_info(f"Unable to delete function varArgs on {function.name}")

    def is_enabled_for_context(self, context):
        if context.has_selection() or context.get_address() is None:
            return False

        location = context.get_location()
        if not isinstance(location, (VariableLocation, FunctionSignatureFieldLocation)):
            return False

        if isinstance(location, FunctionSignatureFieldLocation):
            update_popup_menu(True)
        else:
            update_popup_menu(False)

        function = self.function_plugin.get_function(context)
        return function is not None and function.has_var_args()
```

Please note that Python does not have direct equivalent of Java's `MenuData` class. It has a built-in `tkinter` module for creating GUIs, but it seems like you are trying to create some kind of context menu or popup menu which might be more complex than what can be achieved with just the standard library in Python.