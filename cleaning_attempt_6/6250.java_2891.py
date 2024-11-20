import unittest
from ghidra_test import TestEnv, ClassicSampleX86ProgramBuilder, ProgramTreePlugin, ModuleAlgorithmPlugin
from util.collection_utils import CollectionUtils


class ModuleAlgorithmPluginTest(unittest.TestCase):

    def setUp(self):
        self.env = TestEnv()
        builder = ClassicSampleX86ProgramBuilder()
        program = builder.get_program()
        tool = self.env.launch_default_tool(program)

        tool.add_plugin(ProgramTreePlugin.__name__)
        tool.add_plugin(ModuleAlgorithmPlugin.__name__)
        plugin = self.env.get_plugin(ModuleAlgorithmPlugin)
        actions = get_actions_by_owner(tool, plugin.name)
        service = tool.service[ProgramTreeService]

    def tearDown(self):
        self.env.dispose()

    @unittest.skip("Test is not implemented")
    def test_actions_enabled(self):
        root = program.listing.root_module["Program Tree"]
        gps = [GroupPath([root.name, ".text"])]
        set_group_selection(gps)

        vm_service = tool.service[ViewManagerService]
        vps = vm_service.current_view_provider
        context_object(vps)

        for action in actions:
            self.assertTrue(action.is_enabled())

    @unittest.skip("Test is not implemented")
    def test_active_object(self):
        root = program.listing.root_module["Program Tree"]
        gps = [GroupPath([root.name, ".text"])]
        set_group_selection(gps)

        vm_service = tool.service[ViewManagerService]
        vps = vm_service.current_view_provider
        context_object(vps)

        perform_action(CollectionUtils.any(actions), create_context(context), True)
        wait_for_tasks()
        program.flush_events()

        self.assertIsNotNone(program.listing.module["Program Tree", ".text [Subroutine Tree]    [9]"])

    def set_group_selection(self, gps):
        service.set_group_selection(gps)

    def context_object(self, vps):
        global context
        context = vps.active_popup_object(None)
        self.assertIsNotNone(context)


def get_actions_by_owner(tool, plugin_name):
    # implement this function to return the actions by owner
    pass


def perform_action(action, context, enabled):
    # implement this function to perform an action with a given context and enable status
    pass


def create_context(context):
    # implement this function to create a new context from the given one
    pass


if __name__ == "__main__":
    unittest.main()
