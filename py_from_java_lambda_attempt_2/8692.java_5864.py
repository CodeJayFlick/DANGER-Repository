Here is the translation of the given Java code into equivalent Python:

```Python
import io.StringIO
from ghidra.python import GhidraPythonInterpreter as GPI
from unittest.mock import patch
import unittest


class TestGhidraPythonInterpreter(unittest.TestCase):

    def setUp(self):
        self.out = StringIO()
        GPI.initialize(None, None)
        self.interpreter = GPI.get_instance()
        self.interpreter.set_out(self.out)
        self.interpreter.set_err(self.out)

    def tearDown(self):
        self.out.seek(0)
        self.interpreter.cleanup()
        GPI.dispose()

    @patch('ghidra.python.GhidraPythonInterpreter.push')
    def test_python_push(self, mock_push):
        str = "hi"
        self.interpreter.push(f"print {str}", None)
        self.assertEqual(self.out.getvalue().strip(), str)

    @patch('ghidra.python.GhidraPythonInterpreter.exec_file')
    def test_python_exec_file(self, mock_exec_file):
        resource_file = 'ghidra_scripts/python_basics.py'
        self.interpreter.exec_file(resource_file, None)
        self.assertTrue(self.out.getvalue().contains("Snoopy"))

    @patch('ghidra.python.GhidraPythonInterpreter.push')
    def test_python_site_customize(self, mock_push):
        self.interpreter.push("help", None)
        self.assertTrue(self.out.getvalue().contains("Press 'F1'"))

    @patch('ghidra.python.GhidraPythonInterpreter.cleanup')
    def test_python_cleanup_invalidation(self, mock_cleanup):
        self.interpreter.cleanup()

        try:
            self.interpreter.push("pass", None)
            self.fail("Push still worked after interpreter cleanup.")
        except Exception as e:
            pass
```

Please note that this Python code is not a direct translation of the given Java code. It's an equivalent implementation in Python, using different libraries and frameworks (e.g., `io.StringIO` instead of `ByteArrayOutputStream`, `unittest.TestCase` instead of JUnit).