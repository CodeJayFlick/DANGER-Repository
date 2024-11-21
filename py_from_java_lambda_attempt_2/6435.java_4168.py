Here is the translation of the given Java code into equivalent Python:

```Python
import unittest
from ghidra_framework import *
from ghidra_program_database import ProgramDB
from ghidra_address_factory import AddressFactory
from ghidra_plugin_core_select_flow import SelectByFlowPlugin
from ghidra_code_browser_provider import CodeViewerProvider

class TestSelectByFlowPlugin(unittest.TestCase):

    def setUp(self):
        self.env = TestEnv()
        tool = self.env.get_tool()

        # Add plugins to the environment.
        codeBrowserPlugin = env.get_plugin(CodeBrowserPlugin)
        selectByFlowPlugin = env.get_plugin(SelectByFlowPlugin)

        # Get actions from the plugin
        selectAllFlowsFromAction = getInstanceField("selectAllFlowsFromAction", selectByFlowPlugin)
        selectLimitedFlowsFromAction = getInstanceField("selectLimitedFlowsFromAction", selectByFlowPlugin)
        selectAllFlowsToAction = getInstanceField("selectAllFlowsToAction", selectByFlowPlugin)
        selectLimitedFlowsToAction = getInstanceField("selectLimitedFlowsToAction", selectByFlowPlugin)

        # Get GoToService and CodeViewerProvider
        goToPlugin = env.get_plugin(GoToServicePlugin)
        codeBrowserProvider = codeBrowserPlugin.get_provider()

        self.env.show_tool()
        builder = FollowFlowProgramBuilder()
        program = builder.get_program()
        addressFactory = program.get_address_factory()

        # Open the program in Ghidra.
        pm = tool.get_service(ProgramManager)
        pm.open_program(program.get_domain_file())

    def tearDown(self):
        self.env.dispose()

    def get_action_context(self):
        provider = codeBrowserProvider
        return run_swing(lambda: provider.get_action_context(None))

    @staticmethod
    def default_follow_flow(options):
        options.set_boolean(GhidraOptions.OPTION_FOLLOW_COMPUTED_CALL, False)
        options.set_boolean(GhidraOptions.OPTION_FOLLOW_CONDITIONAL_CALL, False)
        options.set_boolean(GhidraOptions.OPTION_FOLLOW_UNCONDITIONAL_CALL, False)
        options.set_boolean(GhidraOptions.OPTION_FOLLOW_COMPUTED_JUMP, False)
        options.set_boolean(GhidraOptions.OPTION_FOLLOW_CONDITIONAL_JUMP, True)
        options.set_boolean(GhidraOptions.OPTION_FOLLOW_UNCONDITIONAL_JUMP, True)
        options.set_boolean(GhidraOptions.OPTION_FOLLOW_POINTERS, False)

    @staticmethod
    def turn_off_all_follow_flow(options):
        options.set_boolean(GhidraOptions.OPTION_FOLLOW_COMPUTED_CALL, False)
        options.set_boolean(GhidraOptions.OPTION_FOLLOW_CONDITIONAL_CALL, False)
        options.set_boolean(GhidraOptions.OPTION_FOLLOW_UNCONDITIONAL_CALL, False)
        options.set_boolean(GhidraOptions.OPTION_FOLLOW_COMPUTED_JUMP, False)
        options.set_boolean(GhidraOptions.OPTION_FOLLOW_CONDITIONAL_JUMP, False)
        options.set_boolean(GhidraOptions.OPTION_FOLLOW_UNCONDITIONAL_JUMP, False)
        options.set_boolean(GhidraOptions.OPTION_FOLLOW_POINTERS, False)

    @staticmethod
    def turn_on_all_follow_flow(options):
        options.set_boolean(GhidraOptions.OPTION_FOLLOW_COMPUTED_CALL, True)
        options.set_boolean(GhidraOptions.OPTION_FOLLOW_CONDITIONAL_CALL, True)
        options.set_boolean(GhidraOptions.OPTION_FOLLOW_UNCONDITIONal_CALL, True)
        options.set_boolean(GhidraOptions.OPTION_FOLLOW_COMPUTED_JUMP, True)
        options.set_boolean(GhidraOptions.OPTION_FOLLOW_CONDITIONAL_JUMP, True)
        options.set_boolean(GhidraOptions.OPTION_FOLLOW_UNCONDITIONAL_JUMP, True)
        options.set_boolean(GhidraOptions.OPTION_FOLLOW_POINTERS, True)

    @staticmethod
    def follow_computed_calls(follow, options):
        options.set_boolean(GhidraOptions.OPTION_FOLLOW_COMPUTED_CALL, follow)

    @staticmethod
    def follow_conditional_calls(follow, options):
        options.set_boolean(GhidraOptions.OPTION_FOLLOW_CONDITIONAL_CALL, follow)

    @staticmethod
    def follow_unconditional_calls(follow, options):
        options.set_boolean(GhidraOptions.OPTION_FOLLOW_UNCONDITIONAL_CALL, follow)

    @staticmethod
    def follow_computed_jumps(follow, options):
        options.set_boolean(GhidraOptions.OPTION_FOLLOW_COMPUTED_JUMP, follow)

    @staticmethod
    def follow_conditional_jumps(follow, options):
        options.set_boolean(GhidraOptions.OPTION_FOLLOW_CONDITIONAL_JUMP, follow)

    @staticmethod
    def follow_unconditional_jumps(follow, options):
        options.set_boolean(GhidraOptions.OPTION_FOLLOW_UNCONDITIONAL_JUMP, follow)

    @staticmethod
    def follow_pointers(follow, options):
        options.set_boolean(GhidraOptions.OPTION_FOLLOW_POINTERS, follow)

    def addr(self, addr):
        return builder.addr("0x" + str(hex(addr)))

    def go_to(self, address):
        run_swing(lambda: goToService.goTo(address))

    def set_selection(self, selection_set):
        programSelection = ProgramSelection(selection_set)
        tool.fire_plugin_event(ProgramSelectionPluginEvent("test", programSelection, self.program))
```

Please note that this is a direct translation of the Java code into Python.