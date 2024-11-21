Here is the translation of the Java code into Python:

```Python
import ghidra_app.plugin.core.navigation as navigation
from ghidra_framework.options import OptionsChangeListener
from ghidra_framework.plugintool import PluginTool
from ghidra_framework.util.bean.opteditor import OptionsVetoException
from docking.action import ActionContext, NavigatableActionContext
from ghidra.app.context import NavigatableContextAction

class GoToAddressLabelPlugin(navigation.Plugin):
    def __init__(self, plugin_tool: PluginTool):
        super().__init__(plugin_tool)
        
        self.go_to_dialog = None
        self.action = None
        
        self.maximum_goto_entries = 10
        self.c_style_input = False
        self.go_to_memory = True

        self.init()

    def init(self) -> None:
        go_to_service = self.tool.get_service(navigation.GoToService)
        self.go_to_dialog = navigation.GoToAddressLabelDialog(go_to_service, self)

        self.maximum_goto_entries = 10
        self.get_options()
        
        self.tool.add_action(self.action)

    @property
    def maximum_goto_entries(self) -> int:
        return self._maximum_goto_entries

    def read_config_state(self, save_state: object) -> None:
        self.go_to_dialog.read_config_state(save_state)
    
    def write_config_state(self, save_state: object) -> None:
        self.go_to_dialog.write_config_state(save_state)

    def options_changed(self, tool_options: object, op_name: str, old_value: object, new_value: object) -> None:
        if op_name == navigation.GhidraOptions.OPTION_MAX_GO_TO_ENTRIES:
            self._maximum_goto_entries = int(tool_options.get(navigation.GhidraOptions.OPTION_MAX_GO_TO_ENTRIES))
            if self._maximum_goto_entries <= 0:
                raise OptionsVetoException("Search limit must be greater than 0")
            
            self.go_to_dialog.max_enrys_changed()
        elif op_name == navigation.GhidraOptions.OPTION_NUMERIC_FORMATTING:
            self.c_style_input = tool_options.get(navigation.GhidraOptions.OPTION_NUMERIC_FORMATTING)
            self.go_to_dialog.set_c_style_input(self.c_style_input)
        elif op_name == "Goto Dialog Memory":
            self.go_to_memory = tool_options.get("Goto Dialog Memory")
            self.go_to_dialog.set_memory(self.go_to_memory)

    def dispose(self) -> None:
        options = self.tool.get_options(navigation.ToolConstants.TOOL_OPTIONS)
        options.remove_options_change_listener(self)
        
        super().dispose()

    @property
    def go_to_dialog(self):
        return self._go_to_dialog

    @go_to_dialog.setter
    def go_to_dialog(self, value: object) -> None:
        self._go_to_dialog = value
    
    def get_options(self) -> None:
        options = self.tool.get_options(navigation.ToolConstants.TOOL_OPTIONS)
        
        # descriptions
        options.register_option(navigation.GhidraOptions.OPTION_NUMERIC_FORMATTING, False, None,
                                 "Interpret value entered in the Go To dialog as either hex, octal, or binary number.")
        options.register_option(navigation.GhidraOptions.OPTION_MAX_GO_TO_ENTRIES, 10, None,
                                 "Max number of entries remembered in the go to list.")
        options.register_option("Goto Dialog Memory", True, None,
                                 "Remember the last successful go to input in the Go To dialog. If this option is enabled," +
                                 " then the Go To dialog will leave the last successful go to input in the combo box" +
                                 " of the Go To dialog and will select the value for easy paste replacement.")
        
        # options
        self._maximum_goto_entries = int(options.get(navigation.GhidraOptions.OPTION_MAX_GO_TO_ENTRIES))
        self.c_style_input = bool(options.get(navigation.GhidraOptions.OPTION_NUMERIC_FORMATTING))
        self.go_to_dialog.set_c_style_input(self.c_style_input)
        self.go_to_memory = bool(options.get("Goto Dialog Memory"))
        self.go_to_dialog.set_memory(self.go_to_memory)

        options.add_options_change_listener(self)