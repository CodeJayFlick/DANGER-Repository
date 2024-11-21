import unittest
from ghidra_framework import *
from ghidra_program_database import *

class ModuleSortPluginTest(unittest.TestCase):
    def setUp(self):
        self.env = TestEnv()
        self.tool = self.env.get_tool()
        self.tool.add_plugin(ProgramTreePlugin.__name__)
        self.tool.add_plugin(ModuleSortPlugin.__name__)
        managed_plugins = [p for p in self.tool.get_managed_plugins() if isinstance(p, ModuleSortPlugin)]
        self.plugin = managed_plugins[0]
        actions = get_actions_by_owner(self.tool, self.plugin.name)
        service = self.tool.get_service(ProgramTreeService)

        program_builder = ProgramBuilder("notepad", _TOY)
        program_builder.create_memory("test1", "0x1001000", 0x1000)
        program_builder.create_memory("test2", "0x1007000", 0x1000)

        # Main Tree
        program_builder.create_program_tree("Main Tree")
        program_builder.create_fragment("Main Tree", "DLLs", "USER32.DLL", "0x10011a8", "0x10012bf")

        # Strings
        program_builder.create_fragment("Main Tree", "Strings.C", "010074d4", "0x10074d4", "0x10074e3")
        program_builder.create_fragment("Main Tree", "Strings.G", "01007492", "0x1007492", "0x100749c")
        program_builder.create_fragment("Main Tree", "Strings.S", "0100746c", "0x100746c", "0x100747a")
        program_builder.create_fragment("Main Tree", "Strings.L", "0100747e", "0x100747e", "0x100748f")

        memory_call_reference = program_builder.create_memory_call_reference("0x01003597", "0x010033f6")

        self.program = program_builder.get_program()
        pm = self.tool.get_service(ProgramManager)
        pm.open_program(self.program.domain_file)

    def tearDown(self):
        self.env.dispose()

    def test_actions_enabled(self):
        set_view_to_main_tree()
        root_module = self.program.listing.root_module("Main Tree")
        gps = [GroupPath([root_module.name, "DLLs"])]
        selection(gps)
        context = get_active_popup_object(None)

        for action in actions:
            if isinstance(action, DockingActionIf):
                assertTrue(action.is_add_to_popup(context))

    def test_sort_by_name(self):
        set_view_to_main_tree()
        root_module = self.program.listing.root_module("Main Tree")
        gps = [GroupPath([root_module.name, "Strings"])]
        selection(gps)

        transaction_id = start_transaction("Test")
        fragment1 = program.listing.fragment("Main Tree", "0100746c")
        fragment2 = program.listing.fragment("Main Tree", "010074be")

        end_transaction(transaction_id)
        flush_events()

    def test_sort_by_address(self):
        set_view_to_main_tree()
        root_module = self.program.listing.root_module("Main Tree")
        gps = [GroupPath([root_module.name, "Strings"])]
        selection(gps)

        for action in actions:
            if isinstance(action, DockingActionIf) and action.name.index("Address") > 0:
                action.action_performed(None)
                break

    def test_program_closed(self):
        close_program()
        context = get_active_popup_object(None)

        for action in actions:
            assertTrue(not action.is_add_to_popup(context))

def set_view_to_main_tree():
    run_swing(lambda: service.set_viewed_tree("Main Tree"))

def selection(gps):
    run_swing(lambda: service.set_group_selection(gps))
