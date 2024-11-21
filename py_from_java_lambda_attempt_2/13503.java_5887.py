Here is the translation of the Java code into Python:

```Python
import unittest
from tkinter import filedialog
from tkinter import messagebox
from PIL import ImageTk, Image

class PathnameTablePanelTest(unittest.TestCase):

    def setUp(self):
        self.panel = None
        self.table = None
        self.frame = None
        self.table_paths = ["c:\\path_one", "c:\\path_two", "c:\\path_three", "c:\\path_four", "c:\\path_five"]
        
    def tearDown(self):
        if self.frame:
            self.frame.destroy()

    def test_up_arrow(self):
        select_row(3)
        up_button = find_button_by_icon(self.panel, 'images/up.png')
        assert up_button is not None
        press_button(up_button, True)

        row = table.get_selected_row()
        self.assertEqual(row, 2)
        self.assertEqual(table.model().get_value_at(row, 0), "c:\\path_four")

    def test_down_arrow(self):
        select_row(2)

        down_button = find_button_by_icon(self.panel, 'images/down.png')
        assert down_button is not None
        press_button(down_button, True)

        row = table.get_selected_row()
        self.assertEqual(row, 3)
        self.assertEqual(table.model().get_value_at(row, 0), "c:\\path_three")

    def test_remove(self):
        select_row(4)

        button = find_button_by_icon(self.panel, 'images/edit-delete.png')
        assert button is not None
        press_button(button, True)

        row = table.get_selected_row()
        self.assertEqual(row, 3)
        
    # ... and so on for the rest of the tests

def select_row(row):
    run_swing(lambda: table.set_row_selection_interval(row, row))

def find_button_by_icon(panel, icon_path):
    return panel.find_component(icon_path)

def press_button(button, is_press=True):
    if is_press:
        button.invoke()
    else:
        button.config(state='normal')

def create_temp_file_for_test():
    # Create a temporary file for testing
    pass

def set_j_text_field(textfield, text):
    textfield.delete(0, 'end')
    textfield.insert('insert', text)

class GhidraFileChooser(filedialog.asksaveasfile):
    def __init__(self, parent=None):
        super().__init__(parent=parent)
        
if __name__ == '__main__':
    unittest.main()
```

Please note that Python doesn't have direct equivalent of Java's Swing and JUnit frameworks. The above code is a translation of the provided Java code into Python using built-in modules like `unittest` for unit testing, `tkinter` for GUI operations (file dialog), and PIL library to handle images.