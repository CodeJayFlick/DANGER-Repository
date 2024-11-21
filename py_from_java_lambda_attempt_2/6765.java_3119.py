Here is the translation of the given Java code into Python:

```Python
import unittest
from ghidra.app.plugin.core.format import ByteViewerPlugin
from ghidra.program.database import ProgramBuilder
from ghidra.framework.plugintool import PluginTool
from ghidra.program.model.address import Address
from ghidra.program.model.listing import Program

class TestByteViewerConnectedToolBehavior(unittest.TestCase):

    def setUp(self):
        self.env = TestEnv()
        self.tool_one = self.env.get_tool()
        self.setUp_tool(self.tool_one)
        self.plugin_one = self.env.get_plugin(ByteViewerPlugin)
        self.panel_one = self.plugin_one.get_provider().get_byte_viewer_panel()

        self.tool_two = self.env.launch_another_default_tool()
        self.setUp_tool(self.tool_two)
        self.plugin_two = self.env.get_plugin(self.tool_two, ByteViewerPlugin)
        self.panel_two = self.plugin_two.get_provider().get_byte_viewer_panel()

        self.env.connect_tools(self.tool_one, self.tool_two)

    def setUp_tool(self, tool):
        tool.add_plugin(NavigationHistoryPlugin.__name__)
        tool.add_plugin(NextPrevAddressPlugin.__name__)
        tool.add_plugin(ByteViewerPlugin.__name__)

    def test_location_changes(self):
        loc = self.get_field_location(self.plugin_one, 0x01001004)
        run_swing(lambda: panel_one.current_component().set_cursor_position(loc.index, loc.field_num, 0, 0))
        info2 = self.panel_two.current_component().get_cursor_location()
        self.assertEqual(0x01001004, convert_to_addr(self.plugin_two, info2))

    def test_selection_changes(self):
        show_tool(self.tool_two)
        env.show_tool()

        c = panel_one.current_component()
        run_swing(lambda: c.set_cursor_position(get_field_location(plugin_one, 0x01001004).index,
                                                  get_field_location(plugin_one, 0x01001004).field_num, 0, 0))
        start_point = c.get_cursor_point()
        assert start_point is not None

        run_swing(lambda: c.set_cursor_position(get_field_location(plugin_one, 0x010010bb).index,
                                                  get_field_location(plugin_one, 0x010010bb).field_num, 0, 0))
        end_point = c.get_cursor_point()
        assert end_point is not None

        drag_mouse(c, 1, start_point.x, start_point.y, end_point.x, end_point.y, 0)
        wait_for_posted_swing_runnables()

        sel_one = c.get_viewer_selection()
        sel2 = panel_two.current_component().get_viewer_selection()
        self.assertTrue(byte_block_selection_equals(sel_one, sel2))

    def test_edit(self):
        env.show_tool()
        show_tool(self.tool_two)

        action = get_action(plugin_one, "Enable/Disable Byteviewer Editing")
        loc = get_field_location(plugin_one, 0x01001000)
        run_swing(lambda: panel_one.current_component().set_cursor_position(loc.index,
                                                                           loc.field_num, 0, 0))
        action.set_selected(True)
        action.action_performed(ActionContext())

        self.assertTrue(action.is_selected())
        c = panel_one.current_component()
        assertEquals(ByteViewerComponentProvider.DEFAULT_EDIT_COLOR, c.get_focused_cursor_color())

        run_swing(lambda: c.key_pressed(KeyEvent(1), loc.index, loc.field_num,
                                          loc.row, loc.col, c.current_field))
        program.flush_events()

        f2 = panel_two.current_component().get_field(BigInteger.ZERO, 0)
        assertEquals(ByteViewerComponentProvider.DEFAULT_EDIT_COLOR, f2.get_foreground())

    def test_undo_edit(self):
        env.show_tool()
        show_tool(self.tool_two)

        action = get_action(plugin_one, "Enable/Disable Byteviewer Editing")
        loc = get_field_location(plugin_one, 0x01001000)
        run_swing(lambda: panel_one.current_component().set_cursor_position(loc.index,
                                                                           loc.field_num, 0, 0))
        action.set_selected(True)
        action.action_performed(ActionContext())

        self.assertTrue(action.is_selected())
        c = panel_one.current_component()
        assertEquals(ByteViewerComponentProvider.DEFAULT_EDIT_COLOR, c.get_focused_cursor_color())

        run_swing(lambda: c.key_pressed(KeyEvent(1), loc.index, loc.field_num,
                                          loc.row, loc.col, c.current_field))
        program.flush_events()

        f2 = panel_two.current_component().get_field(BigInteger.ZERO, 0)
        assertEquals(ByteViewerComponentProvider.DEFAULT_EDIT_COLOR, f2.get_foreground())

        undo(program)

        f2 = panel_two.current_component().get_field(BigInteger.ZERO, 0)
        assert f2.get_foreground() is None

    def get_field_location(self, plugin, addr):
        panel = plugin.get_provider().get_byte_viewer_panel()
        c = panel.current_component()
        blockset = (ProgramByteBlockSet) plugin.get_provider().get_byte_block_set()
        bb_info = blockset.get_byte_block_info(addr)
        return c.get_field_location(bb_info.block, bb_info.offset)

    def get_addr(self, offset):
        return program.min_address.new_address(offset)

    def convert_to_addr(self, plugin, info):
        return (ProgramByteBlockSet) plugin.get_provider().get_byte_block_set()).address(
            info.block, info.offset)

    def byte_block_selection_equals(self, b1, b2):
        n_ranges = b1.number_of_ranges()
        if n_ranges != b2.number_of_ranges():
            return False
        for i in range(n_ranges):
            range1 = b1.get_range(i)
            range2 = b2.get_range(i)

            bb1 = range1.byte_block
            bb2 = range2.byte_block
            start1 = bb1.location_representation(range1.start_index)
            start2 = bb2.location_representation(range2.start_index)
            end1 = bb1.location_representation(range1.end_index)
            end2 = bb2.location_representation(range2.end_index)

            if not (start1 == start2 and end1 == end2):
                return False
        return True

if __name__ == "__main__":
    unittest.main()
```

Note: This code is a direct translation of the given Java code into Python. However, it may require some adjustments to work correctly in your specific environment.