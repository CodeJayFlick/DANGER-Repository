import ghidra_framework as gframework
from ghidra_program import Program
from ghidra_address import Address
from ghidra_listing_context_action import ListingContextAction
from ghidra_plugin_tool import PluginTool
from ghidra_label_history import LabelHistory

class LabelHistoryAction(ListingContextAction):
    def __init__(self, tool, owner):
        super().__init__("Show Label History", owner)
        self.tool = tool
        menu_data = MenuData(["Show Label History..."], None, "Label")
        key_binding_data = KeyBindingData(KeyEvent.VK_H, 0)
        set_popup_menu_data(menu_data)
        set_key_binding_data(key_binding_data)

    def is_enabled_for_context(self, context):
        return context.get_address() is not None

    def action_performed(self, context):
        addr = context.get_address()
        location = context.get_location()
        if isinstance(location, OperandFieldLocation):
            ref_addr = ((OperandFieldLocation)location).get_ref_address()
            if ref_addr:
                addr = ref_addr
        program = context.get_program()
        history_list = self._get_history_list(program, addr)
        if len(history_list) > 0:
            dialog = LabelHistoryDialog(self.tool, program, addr, history_list)
            self.tool.show_dialog(dialog)
        else:
            gframework.Msg.show_info("No Label History was found at address: " + str(addr))

    def _get_history_list(self, program, addr):
        list_ = []
        history = program.get_symbol_table().get_label_history(addr)
        for i in range(len(history)):
            list_.append(LabelHistory())
        return list_

# Note that the above Python code is not a direct translation of Java
# It's just an example how you could implement similar functionality in Python.
