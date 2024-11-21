import unittest
from ghidra.app.plugin import *
from ghidra.program.model.address import Address
from ghidra.program.model.data import Pointer32DataType
from ghidra.program.model.listing import Program
from ghidra.util.exception import CorruptHostFileException

class MemSearchDecimal2Test(unittest.TestCase):

    def setUp(self):
        super().setUp()
        self.selectRadioButton("Decimal")

    def test_decimal_options_showing(self):
        rb = findAbstractButtonByText(pane, "Byte")
        assert rb is not None
        p = findTitledJPanel(rb, "Format Options")
        assert p is not None and p.isVisible()

        self.assertFalse(rb.isSelected())
        self.assertTrue(rb.isVisible())

    def test_invalid_entry(self):
        setValueText("z")
        assertEquals("", valueField.getText())
        assertEquals("", hexLabel.getText())

    # ... (rest of the tests)

if __name__ == "__main__":
    unittest.main()
