Here is the translation of the Java code into Python:

```Python
class RemoveStackDepthChangeAction:
    def __init__(self, func_plugin):
        self.func_plugin = func_plugin
        super().__init__("Remove Stack Depth Change", func_plugin.name)

    @property
    def popup_menu_data(self):
        return MenuData(["Function Plugin::FUNCTION_MENU_PULLRIGHT", "Remove Stack Depth Change"], None, "Function Plugin::FUNCTION_MENU_SUBGROUP")

    @property
    def key_binding_data(self):
        return KeyBindingData(ord('\x7F'), 0)

    def actionPerformed(self, context):
        program = context.get_program()
        address = context.get_address()

        if CallDepthChangeInfo().get_stack_depth_change(program, address) is None:
            return

        self.func_plugin.execute(program, RemoveStackDepthChangeCommand(program, address))

    @property
    def enabled_for_context(self, context):
        if context.has_selection() or address is None:
            return False

        return CallDepthChangeInfo().get_stack_depth_change(context.get_program(), context.get_address()) is not None


class FunctionPlugin:
    pass


class MenuData:
    def __init__(self, items=None, parent_menu_item=None, subgroup=""):
        self.items = items
        self.parent_menu_item = parent_menu_item
        self.subgroup = subgroup


class KeyBindingData:
    def __init__(self, key_code, modifiers):
        self.key_code = key_code
        self.modifiers = modifiers


class CallDepthChangeInfo:
    @staticmethod
    def get_stack_depth_change(program, address):
        pass


class RemoveStackDepthChangeCommand:
    def __init__(self, program, address):
        self.program = program
        self.address = address

    def execute(self, *args):
        pass


# Example usage:

func_plugin = FunctionPlugin()
action = RemoveStackDepthChangeAction(func_plugin)
```

Please note that this is a direct translation of the Java code into Python. The equivalent classes and methods in Python are used to maintain the same structure as the original Java code.