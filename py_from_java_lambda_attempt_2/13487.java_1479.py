Here is the translation of the given Java code into Python:

```Python
import time
from unittest import TestCase


class ValidateProgramScreenShots(TestCase):

    def __init__(self):
        pass

    @classmethod
    def setUpClass(cls):
        # loadPlugin(ValidateProgramPlugin.class);
        pass

    def test_validate_program(self):
        self.load_plugin()
        self.perform_action("Validate Program", "ValidateProgramPlugin", False)
        time.sleep(1)  # wait for the action to complete
        self.capture_dialog()

    @classmethod
    def tearDownClass(cls):
        # unload plugin here if needed
        pass

    def test_validate_program_done(self):
        self.load_plugin()
        self.perform_action("Validate Program", "ValidateProgramPlugin", False)
        time.sleep(1)  # wait for the action to complete
        dialog = self.get_dialog()
        self.press_button(dialog, "Run Validators")
        condition_test_panel = self.get_instance_field("conditionTestPanel", dialog)
        model = self.get_instance_field("conditionTestModel", condition_test_panel)

        while model.is_in_progress():
            time.sleep(0.1)  # wait for validators to finish

        self.capture_dialog()

    def load_plugin(self):
        pass
        # implementation of loading the plugin here if needed

    def perform_action(self, action_name, plugin_name, is_async=False):
        pass
        # implementation of performing an action here if needed

    def get_dialog(self):
        return None  # implementation of getting a dialog here if needed

    def press_button(self, dialog, button_text):
        pass
        # implementation of pressing a button here if needed

    def get_instance_field(self, field_name, obj):
        return None  # implementation of getting an instance field here if needed

    def capture_dialog(self):
        pass
        # implementation of capturing the dialog here if needed

    def waitForValidators(self, model):
        sleepy_time = 0.1
        total_time = 0
        while model.is_in_progress() and total_time < 10:
            time.sleep(sleepy_time)
            total_time += sleepy_time
        self.assertTrue("Timed out waiting for condition tests", total_time < 10)

```

Please note that the above Python code is a translation of the given Java code, but it does not include any actual implementation. The `load_plugin`, `perform_action`, `get_dialog`, `press_button`, and other methods are placeholders and need to be implemented according to your specific requirements.