Here is the translation of the given Java code into Python:

```Python
import unittest
from ghidra.app.plugin.core.navigation import ProviderNavigationPlugin
from ghidra.program.database import ProgramBuilder
from ghidra.program.model.listing import Program
from ghidra.test.abstract_program_based_test import AbstractProgramBasedTest

class TestProviderNavigationPlugin(AbstractProgramBasedTest):

    def setUp(self):
        self.initialize()
        self.plugin = env.get_plugin(ProviderNavigationPlugin)
        previous_provider_action = get_action(tool, ProviderNavigationPlugin.GO_TO_LAST_ACTIVE_COMPONENT_ACTION_NAME)

        fake_out_context_notification()

    @staticmethod
    def fake_out_context_notification():
        window_manager = tool.getWindowManager()
        test_context_listeners = set(get_instance_field("contextListeners", window_manager).values())
        context_listeners.clear()

        plugin.set_provider_activator(spy_provider_activator())

    def get_program(self):
        return build_program()

    @staticmethod
    def build_program():
        builder = ProgramBuilder("Test", "TOY")
        builder.create_memory(".text", 0x1001000, 66000)
        return builder.get_program()

    @unittest.skipIf(not hasattr(unittest.TestCase, 'assertRaises'), "This test requires Python >= 3.4")
    def test_go_to_last_active_component(self):
        clear_plugin_state()
        assert_previous_provider_action_not_enabled()

        bookmarks = activate_provider("Bookmarks")
        assert_previous_provider_action_not_enabled()  # first provider; nothing to go back to

        data_types = activate_provider("DataTypes Provider")
        assert_previous_provider_action_enabled()

        perform_previous_provider_action()
        self.assertEqual(activated, "bookmarks")

        perform_previous_provider_action()
        self.assertEqual(activated, "data types")

        activate_provider("Symbol Table")

        perform_previous_provider_action()
        self.assertEqual(activated, "data types")

    @staticmethod
    def clear_plugin_state():
        run_swing(lambda: plugin.reset_tracking_state())

    @staticmethod
    def assert_activated(bookmarks):
        self.assertEqual(last_activated, bookmarks)

    @staticmethod
    def perform_previous_provider_action():
        perform_action(previous_provider_action, True)
        run_swing()

    @staticmethod
    def assert_previous_provider_action_enabled():
        self.assertTrue(previous_provider_action.is_enabled_for_context(ActionContext()))

    @staticmethod
    def assert_previous_provider_action_not_enabled():
        self.assertFalse(previous_provider_action.is_enabled_for_context(ActionContext()))

    @staticmethod
    def activate_provider(name):
        provider = tool.get_component_provider(name)
        self.assertIsNotNone(provider)

        run_swing(lambda: force_activate(provider))
        return provider

    @staticmethod
    def force_activate(provider):
        context = ActionContext(provider)
        for listener in test_context_listeners:
            listener.context_changed(context)

class SpyProviderActivator:

    def __init__(self):
        self.last_activated = None

    def accept(self, c):
        self.last_activated = c
        run_swing(lambda: force_activate(c))
```

Note that Python does not have direct equivalents for Java's `@Before` and `@Test`, so the setup method is used to initialize variables before each test. Also, some methods like `fake_out_context_notification()` are static because they do not rely on instance-specific state.