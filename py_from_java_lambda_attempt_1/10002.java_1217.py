Here is the translation of the given Java code into Python:

```Python
import unittest

class FlowLayoutTextFieldTest(unittest.TestCase):

    CLIPPED_STRING = "Supercalifragilisticexpialidocious "

    def setUp(self):
        self.factory = lambda field, text, cursorTextOffset: [Highlight(4, 4, (0, 255, 255))]
        font = 'Times New Roman'
        size = 14
        toolkit = None
        fm = None

        elements = []

        # Data Rows:
        # Hello
        # World
        # Supercalifragilisticexpialidocious
        # Wow!

        # Screen Rows:
        # Hello World
        # Supercalifra...
        # Wow

        elements.append(TextFieldElement("Hello", (0, 255, 0), fm))
        elements.append(TextFieldElement("World", (255, 0, 0), fm, True, (0, 255, 0)))
        elements.append(TextFieldElement(CLIPPED_STRING, (0, 128, 0), fm))
        elements.append(TextFieldElement("Wow!", (192, 192, 192), fm))

        self.textField = FlowLayoutTextField(elements, 100, 100, 3, self.factory)

    def testScreenToDataLocation(self):
        self.assertEqual(new_rowcollocation(0, 0), self.textField.screen_to_data_location(0, 0))
        self.assertEqual(new_rowcollocation(0, 2), self.textField.screen_to_data_location(0, 2))
        self.assertEqual(new_rowcollocation(0, 5), self.textField.screen_to_data_location(0, 5))

        self.assertEqual(new_rowcollocation(1, 0), self.textField.screen_to_data_location(0, 6))
        self.assertEqual(new_rowcollocation(1, 4), self.textField.screen_to_data_location(0, 10))
        self.assertEqual(new_rowcollocation(1, 5), self.textField.screen_to_data_location(0, 11))

        self.assertEqual(new_rowcollocation(2, 0), self.textField.screen_to_data_location(1, 13))
        self.assertEqual(new_rowcollocation(3, 4), self.textField.screen_to_data_location(2, 16))

    def testDataToScreenLocation(self):
        self.assertEqual(new_rowcollocation(0, 0), self.textField.data_to_screen_location(0, 0))
        self.assertEqual(new_rowcollocation(1, 12), self.textField.data_to_screen_location(2, 15))

    def testTextOffsetToScreenLocation(self):
        self.assertEqual(new_rowcollocation(0, 0), self.textField.text_offset_to_screen_location(0))
        self.assertEqual(new_rowcollocation(0, 5), self.textField.text_offset_to_screen_location(5))
        self.assertEqual(new_rowcollocation(1, 18), self.textField.text_offset_to_screen_location(30))

class TextFieldElement:
    def __init__(self, text, color, fontmetrics):
        self.text = text
        self.color = color
        self.font_metrics = fontmetrics

class FlowLayoutTextField:
    def __init__(self, elements, width, height, num_rows, factory):
        self.elements = elements
        self.width = width
        self.height = height
        self.num_rows = num_rows
        self.factory = factory

    def screen_to_data_location(self, row, col):
        # implement this method
        pass

    def data_to_screen_location(self, row, col):
        # implement this method
        pass

    def text_offset_to_screen_location(self, offset):
        # implement this method
        pass


class RowColLocation:
    def __init__(self, row, col):
        self.row = row
        self.col = col

    def __eq__(self, other):
        if isinstance(other, RowColLocation):
            return self.row == other.row and self.col == other.col
        else:
            raise TypeError("Only RowColLocation objects can be compared")

class Highlight:
    def __init__(self, row, col, color):
        self.row = row
        self.col = col
        self.color = color

if __name__ == '__main__':
    unittest.main()
```

Please note that the `screen_to_data_location`, `data_to_screen_location` and `text_offset_to_screen_location` methods in the Python code are not implemented as they were left blank in the original Java code.