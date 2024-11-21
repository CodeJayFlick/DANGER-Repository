import unittest
from ghidra_app import GhidraApp
from ghidra_program_model_listing_function import Function
from ghidra_program_model_symbol import Symbol
from ghidra_services_datatype_manager_service import DataTypeManagerService
from docking_widgets_dialogs_number_input_dialog import NumberInputDialog

class FunctionPluginScreenShots(unittest.TestCase):

    def setUp(self):
        self.app = GhidraApp()
        self.program = self.app.get_current_program()

    def test_edit_storage(self):
        symbol = get_unique_symbol(self.program, "_memcpy")
        function = (Function)symbol.get_object()
        parameter = function.get_parameter(0)

        dt_service = self.app.get_tool().get_service(DataTypeManagerService)
        assert dt_service is not None

        dialog = StorageAddressEditorDialog(self.program, dt_service, parameter, 0)
        run_swing(lambda: tool.show_dialog(dialog), False)

        capture_dialog(600, 400)

    def test_function_editor(self):
        symbol = get_unique_symbol(self.program, "_memcpy")
        go_to_listing(symbol.get_address().get_offset(), "Function Signature", True)
        perform_action("Edit Function", "FunctionPlugin", False)
        capture_dialog(700, 550)

    def test_set_stack_depth_change(self):
        dialog = NumberInputDialog("Set Stack Depth Change at 0x401482",
                                   "Stack Depth Change", 5,
                                   int.min_value(), int.max_value(),
                                   False)
        run_swing(lambda: tool.show_dialog(dialog), False)
        capture_dialog()

    def test_stack_depth_change_or_function_purge(self):
        go_to_listing(0x0040888c)  # position at a call
        perform_action("Set Stack Depth Change", "FunctionPlugin", False)
        press_ok_on_dialog()
        capture_dialog()


if __name__ == "__main__":
    unittest.main()

