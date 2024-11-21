Here is the translation of the Java code into Python:

```Python
import unittest
from hamcrest import assert_that, contains_string
from unittest.mock import patch

class HexOrDecimalInputTest(unittest.TestCase):

    @patch('java.awt.Graphics')
    def test_set_allow_negative(self, mock_graphics):
        input = HexOrDecimalInput()
        new_value = -1
        input.set_value(new_value)
        self.assertEqual(input.get_value(), new_value)

        input.set_allow_negative(False)
        self.assertIsNone(input.get_value())

        new_value = 20
        input.set_value(new_value)
        self.assertEqual(input.get_value(), new_value)

        new_value = -100
        input.set_value(new_value)
        self.assertIsNone(input.get_value())

        input.set_allow_negative(True)
        new_value = -100
        input.set_value(new_value)
        self.assertEqual(input.get_value(), new_value)

    @patch('java.awt.Graphics')
    def test_custom_paint(self, mock_graphics):
        input = HexOrDecimalInput()
        repaint_manager = RepaintManager.current_manager(input)
        repaint_manager.set_double_buffering_enabled(False)

        spy_print_stream = SpyPrintStream()
        debug_graphics = DebugGraphics(scratch_graphics())
        debug_graphics.set_debug_options(DebugGraphics.LOG_OPTION)

        g2d = Graphics2DAdapter(debug_graphics, mock_graphics)
        input.paint_component(g2d)
        self.assertRegex(str(spy_print_stream), 'Dec')

        spy_print_stream.reset()
        input.set_hex_mode()
        input.paint_component(g2d)
        self.assertRegex(str(spy_print_stream), 'Hex')

        spy_print_stream.reset()
        input.set_decimal_mode()
        input.paint_component(g2d)
        self.assertRegex(str(spy_print_stream), 'Dec')

    @patch('java.awt.Graphics')
    def test_toggle_hex_mode_from_keybinding(self, mock_graphics):
        input = HexOrDecimalInput()
        new_value = 10
        input.set_value(new_value)

        self.assertEqual(input.get_value(), new_value)

        toggle_mode(input)
        self.assertEqual(input.get_value(), 0xAL)

        toggle_mode(input)
        self.assertEqual(input.get_value(), new_value)


def scratch_graphics():
    image = BufferedImage(100, 20, BufferedImage.TYPE_INT_BGR)
    return image.getGraphics()


class SpyPrintStream:
    def __init__(self):
        self.baos = ByteArrayOutputStream()

    def reset(self):
        self.baos.reset()
        print(str(self))

    @property
    def toString(self):
        return str(self)


def toggle_mode(input):
    event = KeyEvent(input, 0, System.currentTimeMillis(), 0, KeyEvent.VK_M, 'm')
    key_listeners = input.get_key_listeners()
    for listener in key_listeners:
        listener.key_pressed(event)
```

Note: The Java code has been translated into Python using the following rules:

- Classes and methods are defined as they were in Java.
- Static imports have been replaced with equivalent Python constructs (e.g., `from hamcrest import assert_that, contains_string`).
- Non-static classes have been instantiated like regular objects (`input = HexOrDecimalInput()`).
- Mocking has been done using the `unittest.mock` module and its functions (`@patch('java.awt.Graphics')`, `self.assertRegex(str(spy_print_stream), 'Dec')`).
- The `scratch_graphics` function is now a separate Python function.
- The `SpyPrintStream` class is also defined as it was in Java, with some modifications to fit the Python syntax.