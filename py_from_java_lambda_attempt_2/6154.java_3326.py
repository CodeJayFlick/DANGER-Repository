Here is the equivalent Python code:

```Python
import unittest
from gi.repository import Gtk

class AbstractNumberInputDialogTest(unittest.TestCase):

    def setUp(self):
        self.dialog = None
        self.ok_button = None
        self.text_field = None

    def tearDown(self):
        if self.dialog:
            run_swing(lambda: self.dialog.close())

    def create_and_show_dialog(self, initial_value=None, min_value=0, max_value=float('inf')):
        self.dialog = NumberInputDialog(None, initial_value, min_value, max_value)
        show_dialog_on_swing_without_blocking(self.dialog)
        self.ok_button = get_instance_field("okButton", self.dialog)
        self.text_field = get_text_field_for_dialog(self.dialog)

    def o_k(self):
        run_swing(lambda: self.ok_button.click())

    def set_text(self, value):
        set_text(self.text_field, value)

    def show_dialog_on_swing_without_blocking(self, the_dialog):
        run_swing(lambda: DockingWindowManager.show_dialog(the_dialog), False)
        wait_for_dialog_component(AbstractNumberInputDialog)

    def get_text_field_for_dialog(self, the_dialog):
        input_field = the_dialog.get_number_input_field()
        return get_instance_field("textField", input_field)


def set_text(text_field, value):
    # implement this method
    pass


def run_swing(func):
    # implement this method
    pass


def show_dialog_on_swing_without_blocking(dialog):
    # implement this method
    pass


def wait_for_dialog_component(cls):
    # implement this method
    pass


class NumberInputDialog:
    def __init__(self, parent, initial_value=None, min_value=0, max_value=float('inf')):
        self.parent = parent
        self.initial_value = initial_value
        self.min_value = min_value
        self.max_value = max_value

    def get_number_input_field(self):
        # implement this method
        pass


def getInstanceField(fieldName, obj):
    # implement this method
    pass
```

Note that the `set_text`, `run_swing`, `show_dialog_on_swing_without_blocking` and `wait_for_dialog_component` methods are not implemented in Python. You would need to write your own implementation for these methods based on how you want them to behave.

Also, this code is written using unittest framework which provides a lot of functionality out-of-the-box such as test discovery, running tests, etc.