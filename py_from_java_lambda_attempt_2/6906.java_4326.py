Here is a translation of the Java code into equivalent Python:

```Python
import ghidra


class EditDataTypeAction:
    def __init__(self):
        super().__init__("Edit Data Type")
        self.set_help_location(ghidra.HelpLocation("Decompile", "ActionEditDataType"))
        self.set_popup_menu_data(["Edit Data Type"], "Decompile")

    @property
    def is_valid_context(self, context: ghidra.ActionContext) -> bool:
        return isinstance(context, ghidra.DecompilerActionContext)

    def has_custom_editor_for_base_data_type(
            self,
            tool: ghidra.PluginTool,
            data_type: ghidra.DataType
    ) -> bool:
        base_data_type = DataTypeUtils.get_base_data_type(data_type)
        if base_data_type is None or not isinstance(base_data_type, ghidra.DataType):
            return False

        service = tool.service(DataTypeManagerService)
        return service.is_editable(base_data_type)

    def is_enabled_for_decompiler_context(self, context: ghidra.DecompilerActionContext) -> bool:
        function = context.get_function()
        if isinstance(function, ghidra.UndefinedFunction):
            return False

        data_type = DecompilerUtils.get_data_type(context)
        if data_type is None or not isinstance(data_type, ghidra.DataType):
            return False

        return self.has_custom_editor_for_base_data_type(context.get_tool(), data_type)

    def decompiler_action_performed(self, context: ghidra.DecompilerActionContext) -> None:
        data_type = DecompilerUtils.get_data_type(context)
        base_data_type = DataTypeUtils.get_base_data_type(data_type)
        dt_manager = context.get_program().get_data_type_manager()
        if not isinstance(base_data_type, ghidra.DataType):
            return

        service = context.get_tool().service(DataTypeManagerService)
        if not service.is_editable(base_data_type):
            return

        base_dt_dtm = base_data_type.get_data_type_manager()
        if dt_manager is None or base_dt_dtm is None:
            return

        if dt_manager != base_dt_dtm:
            base_data_type = base_data_type.clone(dt_manager)

        service.edit(base_data_type)
```

Please note that this translation assumes the following:

1. The `ghidra` module contains all necessary classes and functions from the original Java code.
2. The Python version of the code uses a similar structure to the original Java code, with methods named similarly for easier comparison.

This is not an exact translation as there are some differences in syntax between Java and Python.