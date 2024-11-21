import unittest
from ghidra_framework import GhidraScriptUtil
from ghidra_plugin_core_osgi import BundleHost
from ghidra_app_script import GhidraScriptUtil as Gsu
from ghidra_test import TestEnv, AbstractGhidraHeadedIntegrationTest

class PythonPluginTest(AbstractGhidraHeadedIntegrationTest):
    def setUp(self):
        self.env = TestEnv()
        self.tool = self.env.get_tool()
        Gsu.initialize(BundleHost(), None)
        self.tool.add_plugin('PythonPlugin')
        self.plugin = self.env.get_plugin('PythonPlugin')

    def tearDown(self):
        Gsu.dispose()
        self.env.dispose()

    @unittest.skip
    def test_python_plugin_reset(self):
        orig_interpreter = self.plugin.interpreter
        self.plugin.reset()
        new_interpreter = self.plugin.interpreter
        assert not orig_interpreter is new_interpreter

if __name__ == '__main__':
    unittest.main()
