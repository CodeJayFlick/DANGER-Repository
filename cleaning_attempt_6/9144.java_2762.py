import unittest
from ghidra.feature.vt.api import VTControllerImpl, AddressCorrelatorManager
from ghidra.framework.options import Options
from ghidra.test import TestEnv

class VTControllerTest(unittest.TestCase):
    def setUp(self):
        self.env = TestEnv()
        self.tool = self.env.get_tool()
        self.tool.add_plugin('VTPlugin')
        plugin = self.env.get_plugin(VTPlugin)
        self.controller = VTControllerImpl(plugin)

    def tearDown(self):
        self.env.dispose()

    def test_persisting_controller_config_state(self):
        correlator = self.controller.get_correlator()
        assert correlator is not None

        options = correlator.get_options(LastResortAddressCorrelator)
        default_value = 'Test Default Value'
        option_key = 'Test Option Name'
        value = options.get_string(option_key, default_value)
        self.assertEqual(value, default_value)

        new_option_value1 = 'New Option Value'
        options.set_string(option_key, new_option_value1)
        self.assertEqual(options.get_string(option_key, None), new_option_value1)
        correlator.set_options(LastResortAddressCorrelator, options)

        save_state = Options()
        self.controller.write_config_state(save_state)

        new_option_value2 = 'Second New Value'
        options.set_string(option_key, new_option_value2)
        correlator.set_options(LastResortAddressCorrelator, options)

        correlator = self.controller.get_correlator()
        options = correlator.get_options(LastResortAddressCorrelator)
        self.assertEqual(options.get_string(option_key, None), new_option_value2)

        self.controller.read_config_state(save_state)

        # Verify the settings
        correlator = self.controller.get_correlator()
        options = correlator.get_options(LastResortAddressCorrelator)
        self.assertEqual(options.get_string(option_key, None), new_option_value1)

if __name__ == '__main__':
    unittest.main()
