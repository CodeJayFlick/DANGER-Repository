Here is the equivalent Python code:

```Python
import unittest

class DefExportLine:
    def __init__(self, line):
        self.name = None
        self.ordinal = 0
        self.type = None
        
        parts = line.split()
        
        if len(parts) >= 1:
            self.name = parts[0]
            
        for part in parts:
            if part.startswith('@'):
                try:
                    self.ordinal = int(part.lstrip('@'))
                except ValueError:
                    pass
            
            elif part.upper() == 'PRIVATE':
                self.type = 'PRIVATE'
        
    def __str__(self):
        return f"{self.name} @ {self.ordinal} {'(' + self.type + ')' if self.type else ''}"

class TestDefExportLine(unittest.TestCase):

    def test_export_line_with_ordinal(self):
        line = DefExportLine("BobsHouse @1 PRIVATE")
        self.assertEqual(line.name, "BobsHouse")
        self.assertEqual(line.ordinal, 1)
        self.assertEqual(line.type, 'PRIVATE')

    def test_export_line_without_ordinal(self):
        line = DefExportLine("BobsHouse PRIVATE")
        self.assertEqual(line.name, "BobsHouse")
        self.assertEqual(line.ordinal, 0)
        self.assertEqual(line.type, 'PRIVATE')

    def test_export_line_without_private_keyword(self):
        line = DefExportLine("BobsHouse @1")
        self.assertEqual(line.name, "BobsHouse")
        self.assertEqual(line.ordinal, 1)
        self.assertIsNone(line.type)

    def test_export_line_without_ordinal_or_private_keyword(self):
        line = DefExportLine("BobsHouse")
        self.assertEqual(line.name, "BobsHouse")
        self.assertEqual(line.ordinal, 0)
        self.assertIsNone(line.type)

    def test_export_line_with_invalid_format(self):
        try:
            _ = DefExportLine("one two three four")
            self.fail("Did not get a parsing exception with an invalid format")
        except Exception as e:
            pass

if __name__ == '__main__':
    unittest.main()
```

This Python code defines the same classes and methods as the original Java code. The `DefExportLine` class represents a line of exported function information, and it has attributes for name, ordinal, and type. The `TestDefExportLine` class contains test cases to verify that these lines are parsed correctly from strings.