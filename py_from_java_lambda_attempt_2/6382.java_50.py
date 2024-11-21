Here is the translation of the Java code into Python:

```Python
import unittest
from ghidra_app import GhidraApp
from ghidra_framework import Framework
from ghidra_program_database import ProgramDatabase
from ghidra_program_model_address import Address
from ghidra_program_model_listing import Listing
from ghidra_program_model_symbol import Symbol

class AutoRenamePluginTest(unittest.TestCase):

    def setUp(self):
        self.env = GhidraApp()
        self.tool = self.env.get_tool()
        self.program = ProgramDatabase("notepad", "TOY")
        self.plugin = None  # Initialize plugin
        self.rename_action = None  # Initialize rename action
        self.label_action = None  # Initialize label action

    def tearDown(self):
        self.env.dispose()

    def test_action_enabled(self):
        set_view_to_main_tree()
        
        root_module = self.program.get_listing().get_root_module("Main Tree")
        gps = [GroupPath([root_module.name, "DLLs"])]
        set_selection(gps)

        vm_service = self.tool.get_service(ViewManagerService)
        vps = vm_service.get_current_view_provider()

        context = vps.get_active_popup_object(None)
        
        assert not rename_action.is_enabled_for_context(create_context(context))
        assert not label_action.is_enabled_for_context(create_context(context))

        gps = [GroupPath([root_module.name, "DLLs", "USER32.DLL"])]
        set_selection(gps)

        context = vps.get_active_popup_object(None)
        
        assert rename_action.is_enabled_for_context(create_context(context))
        assert not label_action.is_enabled_for_context(create_context(context))

    def test_rename(self):
        set_view_to_main_tree()

        root_module = self.program.get_listing().get_root_module("Main Tree")
        gps = [GroupPath([root_module.name, "DLLs", "USER32.DLL"])]
        program_fragment = self.program.get_listing().get_fragment("Main Tree", "USER32.DLL")

        orig_name = program_fragment.name
        symbol = self.program.get_symbol_table().get_primary_symbol(program_fragment.min_address)
        
        set_selection(gps)

        vm_service = self.tool.get_service(ViewManagerService)
        vps = vm_service.get_current_view_provider()
        context = vps.get_active_popup_object(None)
        
        perform_action(rename_action, create_context(context), True)
        self.program.flush_events()

        assert not program.get_listing().get_fragment("Main Tree", orig_name)
        assert program.get_listing().get_fragment("Main Tree", symbol.name)

    def test_rename_label(self):
        set_view_to_main_tree()

        addr = get_addr(0x010033f6)
        program_fragment = self.program.get_listing().get_fragment("Main Tree", addr)
        
        orig_name = program_fragment.name
        loc = LabelFieldLocation(self.program, addr, "SUB_010033f6")
        
        cb.go_to(loc)

        SwingUtilities.invokeLater(
            lambda: label_action.action_performed(cb.get_provider().get_action_context(None))
        )
        self.program.flush_events()

        assert not program.get_listing().get_fragment("SUB_010033f6", orig_name)
        assert program.get_listing().get_fragment(orig_name, symbol.name)

    def get_addr(self, offset):
        return Address(self.program.min_address + offset)

    def set_view_to_main_tree(self):
        self.tool.set_service(ViewManagerService).set_viewed_tree("Main Tree")

    def set_selection(self, gps):
        self.tool.get_service(ViewManagerService).get_current_view_provider().set_group_selection(gps)
```

Note that Python does not have direct equivalent of Java's `@Before` and `@After`, so we use the standard way to define setup and teardown methods in a test class.