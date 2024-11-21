Here is the translation of the Java code into Python:

```Python
import unittest
from ghidra_framework import *
from ghidra_plugin_core_codebrowser import *

class HeaderTest(unittest.TestCase):
    def setUp(self):
        self.env = TestEnv()
        self.tool = self.env.get_tool()
        self.code_browser_plugin = CodeBrowserPlugin(tool)
        self.program = build_program()

    def tearDown(self):
        self.env.dispose()

    def test_name_mapper(self):
        format_manager = header.get_format_manager()
        factories = [factory for factory in get_instance_field("factories", format_manager)]
        factory = FieldFactoryNameMapper.get_factory_prototype("Mnemonic", factories)
        self.assertIsNotNone(factory)

    def test_make_field_wider(self):
        current_field = code_browser_plugin.current_field
        field_start_x = current_field.start_x
        distance = 10
        row = 3

        drag_mouse(header.header_tab, BUTTON_ONE, field_start_x, row(3), field_start_x + distance, row(3), NO_MODIFIERS)

    def test_make_field_smaller(self):
        current_field = code_browser_plugin.current_field
        start_x = current_field.start_x
        width = current_field.width
        end_x = start_x + width

        drag_mouse(header.header_tab, BUTTON_ONE, end_x - 1, row(3), end_x, row(3), NO_MODIFIERS)

    def test_drag_right(self):
        current_field = code_browser_plugin.current_field
        start_x = current_field.start_x
        width = current_field.width

        drag_mouse(header.header_tab, BUTTON_ONE, start_x + width / 2 - 1, row(3), start_x + width / 2 + 1, row(3), NO_MODIFIERS)

    def test_cursor_near_edge(self):
        cursor = header.header_tab.get_cursor()
        self.assertEqual(cursor.name, "Default Cursor")

        current_field = code_browser_plugin.current_field
        start_x = current_field.start_x

        move_mouse(header.header_tab, start_x - 1, row(3))

        wait_for_swing()

        cursor = header.header_tab.get_cursor()
        self.assertEqual(cursor.name, "East Resize Cursor")

    def test_drag_to_new_line(self):
        current_field = code_browser_plugin.current_field
        start_x = current_field.start_x

        drag_mouse(header.header_tab, BUTTON_ONE, start_x + width / 2 - 1, row(3), start_x + width / 2 + 1, row(8), NO_MODIFIERS)

    def test_drag_to_past_bottom_row(self):
        model = header.get_format_manager().get_code_unit_format()
        self.assertEqual(model.num_rows, 7)
        current_field = code_browser_plugin.current_field
        start_x = current_field.start_x

        drag_mouse(header.header_tab, BUTTON_ONE, start_x + width / 2 - 1, row(3), start_x + width / 2 + 1, row(0), NO_MODIFIERS)

    def test_dragging_left_past_another_field(self):
        current_field = code_browser_plugin.current_field
        start_x = current_field.start_x

        drag_mouse(header.header_tab, BUTTON_ONE, start_x - 1, row(3), start_x + width / 2, row(0), NO_MODIFIERS)

    def test_insert_delete_row(self):
        model = header.get_format_manager().get_code_unit_format()
        self.assertEqual(model.num_rows, 7)
        act = InsertRowAction("Test", header)
        perform_action(act, True)
        self.assertEqual(model.num_rows, 8)
        remove_row_action = RemoveRowAction("Test", header)
        perform_action(remove_row_action, True)
        self.assertEqual(model.num_rows, 7)

    def test_drag_to_new_inserted_line(self):
        model = header.get_format_manager().get_code_unit_format()
        current_field = code_browser_plugin.current_field
        start_x = current_field.start_x

        act = InsertRowAction("Test", header)
        perform_action(act, True)
        self.assertEqual(model.num_rows, 8)

        drag_mouse(header.header_tab, BUTTON_ONE, start_x + width / 2 - 1, row(4), start_x + width / 2 + 1, row(0), NO_MODIFIERS)

    def test_disable_field(self):
        code_browser_plugin.go_to_field(addr("0x1003522"), "Address", 0, 0)
        self.assertTrue(code_browser_plugin.current_field_text == "01003522")

        current_field = code_browser_plugin.current_field
        factory = current_field.get_factory()
        factory.set_enabled(False)

    def test_header_switching(self):
        code_browser_plugin.go_to_field(addr("0x1003522"), "Address", 0, 0)
        model = header.get_format_manager().get_code_unit_format()
        self.assertEqual(model.name, "Instruction/Data")

        code_browser_plugin.go_to_field(addr("0xf0001300"), "Separator", 0, 0)

    def addr(self, address):
        return program.get_address_factory().get_address(address)

if __name__ == "__main__":
    unittest.main()
```

Please note that this is a direct translation of the Java code into Python. It may not be perfect and might require some adjustments to work correctly in your specific environment.