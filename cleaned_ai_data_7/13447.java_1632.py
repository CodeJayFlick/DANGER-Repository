import unittest
from ghidra.app.plugin.core.function.tags import FunctionTagProvider
from ghidra.program.model.address import Address
from ghidra.program.model.listing import Function
from ghidra.program.util import ProgramLocation
from ghidra.util import Swing

class TestFunctionTagPluginScreenShots(unittest.TestCase):

    def test_full_window(self):
        show_provider(FunctionTagProvider)
        wait_for_swing()
        add_table_data()
        capture_isolated_provider(FunctionTagProvider, 950, 400)

    def test_input_field(self):
        show_provider(FunctionTagProvider)
        wait_for_swing()
        provider = get_provider(FunctionTagProvider)
        input_panel = provider.get_input_panel()
        capture_component(input_panel)

    def test_edit_tag(self):
        show_provider(FunctionTagProvider)
        wait_for_swing()
        add_table_data()

        provider = get_provider(FunctionTagProvider)
        source_panel = provider.get_source_panel()
        table = source_panel.get_table()
        bounds = table.get_cell_rect(7, 0)  # Cell 7 is an editable item
        double_click(table, bounds.x, bounds.y)

        edit_dialog = wait_for_dialog_component(InputDialog)
        capture_dialog(edit_dialog)

    def test_delete_warning(self):
        show_provider(FunctionTagProvider)
        wait_for_swing()
        add_table_data()

        provider = get_provider(FunctionTagProvider)
        source_panel = provider.get_source_panel()
        table = source_panel.get_table()
        table.set_row_selection_interval(7, 7)
        button_panel = provider.get_button_panel()
        press_button(button_panel, "deleteBtn", False)

        warning_dialog = wait_for_dialog_component(OptionDialog)
        capture_dialog(warning_dialog)

    def test_edit_not_allowed_warning(self):
        show_provider(FunctionTagProvider)
        wait_for_swing()
        add_table_data()

        provider = get_provider(FunctionTagProvider)
        source_panel = provider.get_source_panel()
        table = source_panel.get_table()
        double_click_item(table, "LIBRARY")  # pick a known read-only tag

        warning_dialog = wait_for_dialog_component(OptionDialog)
        capture_dialog(warning_dialog)

    def double_click_item(self, table, text):
        model = table.get_model()
        row = -1
        for i in range(model.get_row_count()):
            name = str(table.get_value_at(i, 0))
            if name == text:
                row = i
                break

        self.assertTrue(f"Could not find tag '{text}'", row > -1)

        bounds = table.get_cell_rect(row, 0)
        double_click(table, bounds.x, bounds.y)

    def add_table_data(self):
        provider = get_provider(FunctionTagProvider)

        Swing.run_now(lambda: provider.program_activated(program))
        navigate_to_function(provider)

        input_field = provider.get_tag_input_field()
        set_text(input_field, "Tag 2, Tag 3")
        trigger_enter(input_field)

        wait_for_swing()

    def navigate_to_function(self, provider):
        iter = program.get_functions(True)
        while iter.has_next():
            func = iter.next()
            addr = func.get_entry_point()
            loc = ProgramLocation(program, addr)
            provider.location_changed(loc)

            # We only need to find one function, so exit after we've got one.
            return

    def test_capture(self):
        pass  # This method is not implemented in the original Java code.

if __name__ == "__main__":
    unittest.main()
