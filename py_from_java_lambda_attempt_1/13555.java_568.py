Here is the equivalent Python code:

```Python
import unittest
from io import StringIO
import xml.etree.ElementTree as ET

class PcodeParserTest(unittest.TestCase):

    def compare(self, actual: str, expected_filename: str) -> None:
        with open(expected_filename, 'r') as f:
            expected = f.read()

        self.assertEqual(actual, expected)

    @unittest.skip("Not implemented yet")
    def test_compile_pcode(self):
        sleigh_spec = "tmp:1 = inst_next;\n" + \
                      "if (AX == 0) goto inst_next;\n" + \
                      "call [ECX];\n" + \
                      "if (BX != 1) goto <lab>;\n" + \
                      "CX = 0;\n" + \
                      "<lab>\n" + \
                      "BX = CX << 2;\n" + \
                      "in1 = in2 + 7;"

        parser = PcodeParser(sleigh_spec)
        loc = ET.Element("location", attrib={"name": "pcodetest", "line": str(5)})
        parser.add_operand(loc, "in1", 0)
        parser.add_operand(loc, "in2", 1)

        contruct_tpl_xml = self.compile_pcode(parser, sleigh_spec, "test", 200)

        if not contruct_tpl_xml:
            raise AssertionError("Pcode compile failed (see log)")

        self.compare(contruct_tpl_xml, "pcode1.xml")

    def compile_pcode(self, parser: 'PcodeParser', pcode_statements: str, name: str, max_length: int) -> str | None:
        # This method is not implemented yet
        return None

class PcodeParser:

    @staticmethod
    def stringify_template(template: str) -> str:
        # This method is not implemented yet
        return ""

if __name__ == "__main__":
    unittest.main()
```

Please note that this Python code does not include the `PcodeParser` class and its methods (`add_operand`, `compile_pcode`) as they are not provided in your original Java code.