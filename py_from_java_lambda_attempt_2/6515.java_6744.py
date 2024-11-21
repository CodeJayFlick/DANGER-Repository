Here is the translation of the Java code into Python:

```Python
import unittest
from ghidra_framework_options import ToolOptions


class TestToolPluginOptions(unittest.TestCase):

    def setUp(self):
        self.env = None
        self.tool = None

    @classmethod
    def setUpClass(cls):
        cls.env = TestEnv()
        cls.tool = cls.env.get_tool()

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, 'env'):
            cls.env.close_tool(cls.tool)
            cls.env.dispose()

    def test_restore_defaults(self):
        options = self.tool.get_options("Search")

        # Record the state of the original option
        initial_values = {}
        for name in options.get_option_names():
            value = options.get_object(name, None)
            initial_values[name] = value

        # Change some values
        option_name = "Highlight Color"
        highlight_color = options.get_color(option_name, None)
        self.assertIsNotNone(highlight_color)
        options.set_color(option_name, (0, 0, 255))

        option_name = "Highlight Search Results"
        highlight_results = options.get_boolean(option_name, True)
        options.set_boolean(option_name, not highlight_results)

        option_name = "Search Limit"
        search_limit = options.get_int(option_name, 0)
        options.set_int(option_name, search_limit + 100)

        # Restore to default
        options.restore_default_values()

        # Validate the current options against the saved options
        latest_values = {}
        for name in options.get_option_names():
            value = options.get_object(name, None)
            latest_values[name] = value

        diffs = get_diffs(initial_values, latest_values)

        if len(diffs) != 0:
            print("Options values are not restored back to the original settings - diffs")
            for diff in diffs:
                print("\tdiff: " + diff)
            self.fail("Options values not restored (see error output)")

    def test_options_without_registered_owner_go_away(self):
        options = load_search_options()

        changed_option = change_string_test_option(options)

        # See if the options are there again after saving and reloading.  They should be there, since
        # the previous operation set the value.  We are careful here to simply check for the option's existence,
        # but not to retrieve it, as doing so would trigger the option to be stored again.
        options = save_and_load_options()
        verify_string_option_still_changed_without_using_options_api(options, changed_option[0])

        options = save_and_load_options()
        verify_unused_option_no_longer_has_entry(options, changed_option[0])

    def test_save_only_non_default_options(self):
        options = load_search_options()

        changed_option = change_string_test_option(options)

        options = save_and_load_options()
        assert_all_default_options(options)

        self.assertTrue("Expected non-default value for option: " + changed_option[0], options.contains(changed_option[0]))

    def test_accessing_option_without_registering(self):
        options = load_search_options()

        help_location = None
        default_value = 1
        option_name = "Foo Int"
        options.register_option(option_name, OptionType.INT_TYPE, default_value, help_location, "Description")

        self.assertTrue("Expected non-default value for option: " + option_name, options.contains(option_name))

    def test_set_file_option_to_null(self):
        # Make sure the user can set the file option to null, to allow the clearing of a value
        options = load_search_options()

        help_location = None
        default_value = None
        option_name = "Foo File"
        options.register_option(option_name, OptionType.FILE_TYPE, default_value, help_location, "Description")

        self.assertTrue("Expected non-default value for option: " + option_name, options.contains(option_name))

    def test_set_non_nullable_option_to_null(self):
        # Some options cannot be null.  Verify that is the case
        options = load_search_options()

        help_location = None
        default_value = 1
        option_name = "Foo Int"
        options.register_option(option_name, OptionType.INT_TYPE, default_value, help_location, "Description")

        try:
            options.put_object(option_name, None)
            self.fail("Did not get expected exception")
        except ValueError as e:
            pass

    def test_clearing_key_binding_option(self):
        # Clear the key binding
        option_name = clear_key_binding(options)

        self.assertIsNone(key_stroke_value)


def load_search_options():
    return tool.get_options("Search")


def change_string_test_option(options):
    options.register_option(NEW_TEST_OPTION_NAME, "HEY", None, "description")
    options.set_string(NEW_TEST_OPTION_NAME, TEST_OPTION_STRING_VALUE)
    return (NEW_TEST_OPTION_NAME, TEST_OPTION_STRING_VALUE)


def save_and_load_options():
    tool = save_tool(env.get_project(), tool)  # saving the tool saves the options
    return load_search_options()


def verify_unused_option_no_longer_has_entry(options, option_name):
    if options.contains(option_name):
        self.fail("Options does not have an entry for test option - value: " + options.get_object(option_name, None))


# Helper functions

def get_diffs(initial_values, latest_values):
    diffs = []
    key_set = initial_values.keys()
    for key in key_set:
        value = initial_values[key]
        new_value = latest_values.get(key)
        if not value == new_value:
            diffs.append(str(key) + " - old: " + str(value) + " - new: " + str(new_value))
    return diffs


def print_non_default_values(options):
    names = options.get_option_names()
    for name in names:
        if not options.is_default_value(name):
            Msg.debug(this, "non-default - name: " + name + ", value: " + options.get_object(name, None))


# End of TestToolPluginOptions class

if __name__ == "__main__":
    unittest.main()

```

Please note that the above Python code is a direct translation from Java to Python. It may not be perfect and might require some adjustments based on your specific requirements.