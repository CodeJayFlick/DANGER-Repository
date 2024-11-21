Here is the translation of the Java code into Python:

```Python
import os
from threading import Thread
from time import sleep

class KeyBindingUtilsTest:
    def __init__(self):
        self.TEST_FILENAME = "KeyBindingUtilsTest_Test_Filename" + ".xml"
        self.debug_file = None

    @classmethod
    def setUpClass(cls):
        pass

    def setUp(self):
        # Set up the tool and environment.
        self.env = TestEnv()
        self.tool = self.env.get_tool()

        # Add some plugins to work with key bindings.
        self.tool.add_plugin(NavigationHistoryPlugin)
        self.tool.add_plugin(CodeBrowserPlugin)
        self.tool.add_plugin(MemoryMapPlugin)
        self.tool.add_plugin(GoToAddressLabelPlugin)
        self.tool.add_plugin(DataTypeManagerPlugin)
        self.tool.add_plugin(DataPlugin)
        self.tool.add_plugin(FunctionPlugin)

    def tearDown(self):
        # Clean up after the test.
        if self.debug_file is not None:
            os.remove(self.debug_file)
        self.env.dispose()

    @staticmethod
    def parse_key_stroke(ks):
        return KeyBindingUtils.parse_key_stroke(ks).decode("utf-8")

    @classmethod
    def import_options(cls, file_path):
        # Create a runnable to get the options.
        class ImportRunnable:
            def __init__(self, file_path):
                self.file_path = file_path

            def run(self):
                return KeyBindingUtils.import_key_bindings()

        thread = Thread(target=ImportRunnable().run)
        thread.start()
        sleep(1)  # Wait for the import to finish.
        options = thread.join()  # Get the imported options.

    @classmethod
    def export_options(cls, options):
        # Export the key bindings and read them back in.
        file_path = KeyBindingUtils.export_key_bindings(options)
        return file_path

    @staticmethod
    def compare_options(old_options, panel_key_stroke_map):
        property_names = old_options.get_option_names()
        for name in property_names:
            if not panel_key_stroke_map.contains(name):
                return False  # Options do not match.
            options_ks = old_options.get_key_stroke(name)
            panel_ks = panel_key_stroke_map[name]
            if (options_ks is None) != (panel_ks is None):
                return False  # Options do not match.

        return True

    @staticmethod
    def assert_options_match(message, options1, options2):
        property_names = get_option_names(options1)
        other_property_names = get_option_names(options2)

        if len(property_names) != len(other_property_names):
            raise AssertionError("Options have different number of properties")

        for name in property_names:
            match = options2.contains(name)
            value = options1.get_object(name, None)
            value2 = options2.get_object(name, None)
            match &= (value == value2)

            if not match:
                print(f"Found non-matching option: {name}, value 1={value}, value 2={value2}")
                raise AssertionError(message)

    @staticmethod
    def assert_options_dont_match(message, options1, options2):
        property_names = get_option_names(options1)
        other_property_names = get_option_names(options2)

        if len(property_names) != len(other_property_names):
            return  # Options do not match.

        for name in property_names:
            match = options2.contains(name)
            value = options1.get_object(name, None)
            value2 = options2.get_object(name, None)

            match &= (value == value2)

            if not match:
                raise AssertionError(message)