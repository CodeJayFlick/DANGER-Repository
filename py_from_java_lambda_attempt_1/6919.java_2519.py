Here is a translation of the Java code into equivalent Python:

```Python
class IsolateVariableAction:
    def __init__(self):
        super().__init__("Split Out As New Variable")
        self.set_help_location(HelpLocation("DECOMPILER", "ActionIsolate"))
        self.set_popup_menu_data(MenuData(["Split Out As New Variable"], "Decompile"))

    @property
    def is_enabled_for_decompiler_context(self, context):
        function = context.get_function()
        if not (function and isinstance(function, UndefinedFunction)):
            return False

        token_at_cursor = context.get_token_at_cursor()
        if not token_at_cursor:
            return False

        high_variable = token_at_cursor.get_high_variable()
        if not isinstance(high_variable, HighLocal):
            return False

        high_symbol = high_variable.get_symbol()
        if not high_symbol:
            return False
        if high_symbol.is_isolated():
            return False

        vn = token_at_cursor.get_varnode()
        if not vn:
            return False

        merge_group = vn.get_merge_group()
        is_merge_split = False
        for var in high_variable.get_instances():
            if var.get_merge_group() != merge_group:
                is_merge_split = True
                break
        if not is_merge_split:
            return False
        return True

    def decompiler_action_performed(self, context):
        token_at_cursor = context.get_token_at_cursor()
        high_symbol = token_at_cursor.get_high_variable().get_symbol()

        new_variable_task = IsolateVariableTask(
            context.get_tool(),
            context.get_program(),
            context.get_decompiler_panel(),
            token_at_cursor,
            high_symbol,
            SourceType.USER_DEFINED
        )

        new_variable_task.run_task(False)
```

Please note that Python does not have direct equivalent of Java's abstract class, interface or annotation.