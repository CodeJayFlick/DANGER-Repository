import unittest
from ghidra_test import TestEnv, PluginTool


class AutoServiceTest(unittest.TestCase):

    def setUp(self):
        self.env = TestEnv()
        self.tool = self.env.get_tool()

    def tearDown(self):
        self.env.dispose()

    @unittest.skip("This test is not implemented yet")
    def test_service_provided(self):
        plugin = add_plugin(self.tool, AnnotatedServicesProvidedPlugin)
        self.assertEqual(plugin.test_service, self.tool.get_service(TestService))

    @unittest.skip("This test is not implemented yet")
    def test_service_consumed_by_field(self):
        plugin = add_plugin(self.tool, AnnotatedServicesProvidedPlugin)
        comp = AnnotatedServicesConsumedByFieldComponent(plugin)
        self.assertEqual(plugin.test_service, comp.test_service)

    @unittest.skip("This test is not implemented yet")
    def test_service_consumed_by_method(self):
        plugin = add_plugin(self.tool, AnnotatedServicesProvidedPlugin)
        comp = AnnotatedServicesConsumedByMethodComponent(plugin)
        self.assertEqual(plugin.test_service, comp.test_service)

    @unittest.skip("This test is not implemented yet")
    def test_service_consumed_before_provided(self):
        dummy = add_plugin(self.tool, DummyPlugin)
        comp = AnnotatedServicesConsumedByFieldComponent(dummy)
        plugin = add_plugin(self.tool, AnnotatedServicesProvidedPlugin)
        self.assertEqual(plugin.test_service, comp.test_service)

    @unittest.skip("This test is not implemented yet")
    def test_service_removed(self):
        plugin = add_plugin(self.tool, AnnotatedServicesProvidedPlugin)
        comp = AnnotatedServicesConsumedByFieldComponent(plugin)
        self.assertEqual(plugin.test_service, comp.test_service)
        self.tool.remove_plugins([plugin])
        self.assertIsNone(comp.test_service)


class TestService:
    pass


class TestServiceImpl(TestService):
    def __init__(self):
        pass


class AnnotatedServicesProvidedPlugin(PluginTool):

    @AutoServiceProvided
    def __init__(self, tool):
        super().__init__(tool)
        self.auto_service_wiring = AutoService.wire_services_provided_and_consumed(self)


class DummyPlugin(PluginTool):
    def __init__(self, tool):
        super().__init__(tool)


class AnnotatedServicesConsumedByFieldComponent:
    @AutoServiceConsumed
    def __init__(self, plugin):
        self.auto_service_wiring = AutoService.wire_services_consumed(plugin, self)
        self.test_service = None


class AnnotatedServicesConsumedByMethodComponent:
    def __init__(self, plugin):
        self.auto_service_wiring = AutoService.wire_services_consumed(plugin, self)
        self._test_service = None

    @AutoServiceConsumed
    def set_test_service(self, test_service):
        self._test_service = test_service


if __name__ == '__main__':
    unittest.main()
