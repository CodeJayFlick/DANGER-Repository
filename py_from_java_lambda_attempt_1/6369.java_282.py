Here is the translation of the Java code into Python:

```Python
import unittest
from ghidra_app import *
from ghidra_framework_plugintool import *

class LabelActionTest(unittest.TestCase):

    def setUp(self):
        self.env = TestEnv()
        tool = self.env.get_tool()
        tool.add_plugin(LabelMgrPlugin)
        tool.add_plugin(CodeBrowserPlugin)
        label_mgr_plugin = self.env.get_plugin(LabelMgrPlugin)
        code_browser_plugin = self.env.get_plugin(CodeBrowserPlugin)

        builder = ClassicSampleX86ProgramBuilder()
        program = builder.get_program()

        add_label = get_action(label_mgr_plugin, "Add Label")
        edit_label = get_action(label_mgr_plugin, "Edit Label")
        edit_external_location = get_action(label_mgr_plugin, "Edit External Location")
        remove_label = get_action(label_mgr_plugin, "Remove Label")
        set_label = get_action(label_mgr_plugin, "Set Operand Label")

        self.env.show_tool()

    def tearDown(self):
        self.env.dispose()

    @unittest.skip("Not implemented yet.")
    def test_set_label_action_enabled(self):

        addr = program.get_min_address().get_new_address(0x0100416c)
        pm = tool.get_service(ProgramManager)
        pm.open_program(program)

        ref_mgr = program.get_reference_manager()
        ref = ref_mgr.get_primary_reference_from(addr, 0)

        loc = OperandFieldLocation(program, addr, None, ref.get_to_address(), "destStr", 0, 0)
        tool.fire_plugin_event(PluginEvent("test", loc, program))
        code_browser_plugin.update_now()

    @unittest.skip("Not implemented yet.")
    def test_show_label_history(self):

        self.env.open(program)

        cb = CodeBrowser()
        cb.go_to(LabelFieldLocation(program, program.get_address_factory().get_address("0x1002d2b"), "AnotherLocal", None, 0))
        loc = cb.current_location
        assert isinstance(loc, LabelFieldLocation)
        assertEquals(0x01002d2b, loc.address.offset)

    @unittest.skip("Not implemented yet.")
    def test_notepad_locations(self):

        context = ActionContext()
        self.assertFalse(add_label.is_enabled_for_context(context))
        self.assertFalse(edit_label.is_enabled_for_context(context))
        self.assertFalse(remove_label.is_enabled_for_context(context))
        self.assertFalse(set_label.is_enabled_for_context(context))

        self.env.open(program)
        code_browser_plugin.update_now()

    def location_generated(self, loc):
        tool.fire_plugin_event(PluginEvent("test", loc, program))
        code_browser_plugin.update_now()
```

Note that the `@Override` annotation is not necessary in Python.