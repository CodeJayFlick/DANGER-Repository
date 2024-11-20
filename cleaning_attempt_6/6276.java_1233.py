import unittest
from ghidra.app.plugin.core.colorizer import ColorizingPluginTest
from ghidra.framework.options import ToolOptions
from ghidra.program.model.address import AddressFactory
from ghidra.program.model.data import WordDataType
from ghidra.program.model.listing import Program

class TestColorizingPlugin(unittest.TestCase):

    def setUp(self):
        self.env = None  # Initialize env variable
        self.tool = None  # Initialize tool variable
        self.cb = None  # Initialize code browser plugin variable
        self.colorizer_plugin = None  # Initialize colorizer plugin variable
        self.colorizing_service = None  # Initialize colorizing service variable

    def test_set_color(self):
        load_program("notepad")
        assert_clear_actions_enabled(False)
        assert_navigation_actions_enabled(False)

        set_color(Color.RED, cb.get_current_address())
        assert_color_for_address(Color.RED, cb.get_current_address())

        create_selection()
        set_color(Color.BLUE, selection_color=Color.BLUE)
        assert_color_for_selection(Color.BLUE)

    def test_clear_color(self):
        load_program("notepad")
        address1 = cb.get_current_address()
        color = Color.RED
        set_color(color, address1)
        assert_color_for_address(color, address1, address2=color.add(8))

        clear_color(address2)
        assert_no_color_for_address()

    def test_clear_all(self):
        load_program("notepad")
        make_a_few_non_contiguous_color_changes()
        clear_all_colors()
        assert_no_color_for_address()

    # ... (rest of the methods)

def set_color(color, address=None):
    if not address:
        cb.go_to(cb.get_current_address())
    else:
        cb.go_to(address)
    perform_action(set_color_action, context=False)

def create_selection():
    fp = cb.get_field_panel()
    p1 = fp.get_cursor_location()
    p2 = fp.get_cursor_location()
    selection = FieldSelection()
    selection.add_range(p1, p2)
    set_selection(fp, selection)

# ... (rest of the methods)

if __name__ == "__main__":
    unittest.main()
