Here is the translation of the given Java code into Python:

```Python
class CreateMultipleFunctionsAction:
    def __init__(self, name, func_plugin):
        self.func_plugin = func_plugin
        super().__init__(name)

    @property
    def popup_menu_data(self):
        return MenuData([name], None, 'FUNCTION_MENU_SUBGROUP', 0, 'FUNCTION_SUBGROUP_BEGINNING')

    def set_enabled(self, value):
        self.enabled = value

    def action_performed(self, context):
        selection = context.get_selection()
        if not self.is_enabled_for_context(context):
            return
        program = context.get_program()
        if program is None:
            return

        cmd = CreateMultipleFunctionsCmd(selection, 'USER_DEFINED')
        self.func_plugin.execute(program, cmd)

    def is_enabled_for_context(self, context):
        return bool(context.has_selection())

class MenuData:
    def __init__(self, items=None, mnemonic=0, subgroup='FUNCTION_MENU_SUBGROUP', start_subgroup='FUNCTION_SUBGROUP_BEGINNING'):
        self.items = items
        self.mnemonic = mnemonic
        self.subgroup = subgroup
        self.start_subgroup = start_subgroup

class CreateMultipleFunctionsCmd:
    def __init__(self, selection, source_type):
        self.selection = selection
        self.source_type = source_type

# Example usage:

func_plugin = FunctionPlugin()  # This class is not defined in the given code.
name = 'Create Multiple Functions'
action = CreateMultipleFunctionsAction(name, func_plugin)
```

Please note that Python does not have direct equivalent of Java's `package`, `import` statements. Also, Python classes do not need to be declared inside a package or module.