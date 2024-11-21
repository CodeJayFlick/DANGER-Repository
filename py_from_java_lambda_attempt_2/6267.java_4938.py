Here is the translation of the Java code into Python:

```Python
import unittest
from ghidra.app.plugin.core.codebrowser import CodeBrowserNavigationTest
from ghidra.program.util import addr
from ghidra.framework.options import Options
from ghidra.app.plugin.core.table import TableComponentProvider
from ghidra. program.util import ProgramLocation

class TestCodeBrowserNavigation(unittest.TestCase):

    def test_operand_navigation(self):
        cb.go_to(ProgramLocation(addr("1002000")))
        self.assertEqual(addr("1002000"), cb.get_current_address())

        click(cb, 2)
        self.assertEqual(addr("1003000"), cb.get_current_address())

        cb.go_to(ProgramLocation(addr("1004000")))
        self.assertEqual(addr("1004000"), cb.get_current_address())

        click(cb, 2)
        self.assertEqual(addr("1004010"), cb.get_current_address())

    def test_xref_naviagation(self):
        go_to(XRefFieldLocation(program, addr("1004010"), None, addr("1004000"), 0, 2))
        self.assertEqual(addr("1004010"), cb.get_current_address())

        click(cb, 2)
        self.assertEqual(addr("1004000"), cb.get_current_address())

    def test_function_naviagation(self):
        cb.go_to(ProgramLocation(program, addr("1006300")))
        self.assertEqual(addr("1006300"), cb.get_current_address())

        prev_function()
        self.assertEqual(addr("1006200"), cb.get_current_address())

        prev_function()
        self.assertEqual(addr("1006100"), cb.get_current_address())

    def test_xref_naviagation_more_field(self):
        opt = get_tool().get_options(Options.CATEGORY_BROWSER_FIELDS)
        opt.set_int("XREFs Field" + Options.DELIMITER + "Maximum Number of XREFs to Display", 2)

        cb.go_to(XRefFieldLocation(program, addr("1004010"), None, addr("1004030"), 2, 2))
        self.assertEqual(addr("1004010"), cb.get_current_address())

    def test_multiple_refs(self):
        cb.go_to(OperandFieldLocation(program, addr("1004050"), None, None, None, 0, 0))
        self.assertEqual(addr("1004050"), cb.get_current_address())

        click(cb, 2)

        table = waitFor_results()
        column_model = table.column_model
        model = table.model

    def test_bad_address(self):
        cb.go_to(OperandFieldLocation(program, addr("1002010"), None, None, None, 0, 0))
        self.assertEqual(addr("1002010"), cb.get_current_address())

        click(cb, 2)
        self.assertEqual(addr("1002010"), cb.get_current_address())
```

Note: This Python code is not a direct translation of the Java code. It's more like an interpretation based on my understanding of what the original Java code does.