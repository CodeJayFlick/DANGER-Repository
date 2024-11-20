import unittest

class VerticalLayoutTextFieldTest(unittest.TestCase):

    CLIPPED_STRING = "Supercalifragilisticexpialidocious"

    def setUp(self):
        self.factory = lambda f, text, cursorTextOffset: [Highlight(4, 4, (0, 255, 255))]
        font = 'Times New Roman'
        size = 14
        toolkit = Toolkit()
        font_metrics = toolkit.get_font_metrics(font, size)

        elements = []

        elements.append TextFieldElement('Hello', Color.BLUE, font_metrics))
        elements.append TextFieldElement(
            AttributedString("World", Color.RED, font_metrics), 1, 0)
        elements.append TextFieldElement(AttributedString(CLIPPED_STRING, Color.GREEN, font_metrics), 2, 0))
        elements.append TextFieldElement(AttributedString('Wow!', Color.GRAY, font_metrics), 3, 0))

        self.field = VerticalLayoutTextField(elements, 100, 100, 5, self.factory)

    def testScreenToDataLocation(self):
        self.assertEqual(RowColLocation(0, 0), self.field.screen_to_data_location(0, 0))
        self.assertEqual(RowColLocation(0, 2), self.field.screen_to_data_location(0, 2))
        self.assertEqual(RowColLocation(0, 5), self.field.screen_to_data_location(0, 5))
        self.assertEqual(RowColLocation(0, 5), self.field.screen_to_data_location(0, 6))
        self.assertEqual(RowColLocation(0, 5), self.field.screen_to_data_location(0, 75))

        self.assertEqual(RowColLocation(1, 0), self.field.screen_to_data_location(1, 0))
        self.assertEqual(RowColLocation(1, 5), self.field.screen_to_data_location(1, 6))
        self.assertEqual(RowColLocation(1, 5), self.field.screen_to_data_location(1, 16))

        self.assertEqual(RowColLocation(2, 0), self.field.screen_to_data_location(2, 0))
        self.assertEqual(RowColLocation(2, 4), self.field.screen_to_data_location(2, 4))
        self.assertEqual(RowColLocation(2, 34), self.field.screen_to_data_location(2, 75))

        self.assertEqual(RowColLocation(3, 0), self.field.screen_to_data_location(3, 0))
        self.assertEqual(RowColLocation(3, 4), self.field.screen_to_data_location(50, 75))

    def testDataToScreenLocation(self):
        self.assertEqual(RowColLocation(0, 0), self.field.data_to_screen_location(0, 0))
        self.assertEqual(RowColLocation(0, 2), self.field.data_to_screen_location(0, 2))
        self.assertEqual(RowColLocation(0, 5), self.field.data_to_screen_location(0, 5))

        self.assertEqual(RowColLocation(1, 0), self.field.data_to_screen_location(1, 0))
        self.assertEqual(RowColLocation(1, 4), self.field.data_to_screen_location(1, 4))
        self.assertEqual(RowColLocation(1, 5), self.field.data_to_screen_location(1, 5))

        self.assertEqual(RowColLocation(2, 0), self.field.data_to_screen_location(2, 0))
        self.assertEqual(RowColLocation(2, 4), self.field.data_to_screen_location(2, 4))
        self.assertEqual(RowColLocation(2, 12), self.field.data_to_screen_location(2, 12))
        self.assertEqual(DefaultRowColLocation(2, 15), self.field.data_to_screen_location(2, 15))

        self.assertEqual(RowColLocation(3, 0), self.field.data_to_screen_location(3, 0))
        self.assertEqual(RowColLocation(3, 4), self.field.data_to_screen_location(3, 4))

    def testTextOffsetToScreenLocation(self):
        self.assertEqual(RowColLocation(0, 0), self.field.text_offset_to_screen_location(0))
        self.assertEqual(RowColLocation(0, 5), self.field.text_offset_to_screen_location(5))

        self.assertEqual(RowColLocation(1, 0), self.field.text_offset_to_screen_location(6))
        self.assertEqual(RowColLocation(1, 4), self.field.text_offset_to_screen_location(10))
        self.assertEqual(RowColLocation(1, 5), self.field.text_offset_to_screen_location(11))

        self.assertEqual(RowColLocation(2, 0), self.field.text_offset_to_screen_location(12))

        self.assertEqual(RowColLocation(3, 4), self.field.text_offset_to_screen_location(1000))

    def testGetY_And_GetRow(self):
        y = self.field.get_y(0)
        row = self.field.get_row(y)
        self.assertEqual("Wrong row for y value: " + str(y), 0, row)

        y = self.field.get_y(1)
        row = self.field.get_row(y)
        self.assertEqual("Wrong row for y value: " + str(y), 1, row)

        y = self.field.get_y(2)
        row = self.field.get_row(y)
        self.assertEqual("Wrong row for y value: " + str(y), 2, row)

        y = self.field.get_y(3)
        row = self.field.get_row(y)
        self.assertEqual("Wrong row for y value: " + str(y), 3, row)

        # try values past the end
        y_for_row_too_big = self.field.get_y(10)
        self.assertEqual(y, y_for_row_too_big)
        row_for_y_too_big = self.field.get_row(1000)
        self.assertEqual(3, row_for_y_too_big)

        # try values before the beginning
        y_for_row_too_small = self.field.get_y(-1)
        expected_y = -self.field.height_above()
        self.assertEqual(expected_y, y_for_row_too_small)
        row_for_y_too_small = self.field.get_row(-1000)
        self.assertEqual(0, row_for_y_too_small)

if __name__ == '__main__':
    unittest.main()
