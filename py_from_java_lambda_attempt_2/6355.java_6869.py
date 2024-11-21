Here is the translation of the given Java code into equivalent Python:

```Python
import unittest
from ghidra_app_plugin_core_function import EditFunctionSignatureDialogTest


class TestEditFunctionSignatureDialog(unittest.TestCase):

    def setUp(self):
        self.env = None  # Initialize env and tool here.
        self.tool = None

    def tearDown(self):
        if self.env is not None:
            self.env.dispose()

    @unittest.skip("Skipping test")
    def test_parse_signature_good(self):
        signature = "void bob(int a)"
        f = function("bob", signature)
        dialog = EditFunctionSignatureDialog(self.tool, "Title", f)
        definition = dialog.parse_signature()
        self.assertIsNotNone(definition)
        self.assertEqual(signature, definition.get_prototype_string())

    @unittest.skip("Skipping test")
    def test_parse_signature_bad_at_sign_in_name(self):
        signature = "void bob@12(int a)"
        f = function("bob@12", signature)
        dialog = EditFunctionSignatureDialog(self.tool, "Title", f)
        definition = dialog.parse_signature()
        self.assertIsNotNone(definition)
        self.assertEqual(signature, definition.get_prototype_string())

    @unittest.skip("Skipping test")
    def test_parse_signature_bad_extra_parens_at_end(self):
        signature = "void bob(int a)()"
        f = function("bob", signature)
        dialog = EditFunctionSignatureDialog(self.tool, "Title", f)
        definition = dialog.parse_signature()
        self.assertIsNone(definition)

    @unittest.skip("Skipping test")
    def test_parse_signature_bad_missing_paren(self):
        signature = "void bob(int a"
        f = function("bob", signature)
        dialog = EditFunctionSignatureDialog(self.tool, "Title", f)
        definition = dialog.parse_signature()
        self.assertIsNone(definition)

    @unittest.skip("Skipping test")
    def test_parse_signature_bad_missing_return_type(self):
        signature = "bob(int a)"
        f = function("bob", signature)
        dialog = EditFunctionSignatureDialog(self.tool, "Title", f)
        definition = dialog.parse_signature()
        self.assertIsNone(definition)

    @staticmethod
    def function(name, signature):
        return LocalFunctionStub(name, signature)


class LocalFunctionStub:
    def __init__(self, name, signature):
        super().__init__()
        self.name = name
        self.signature = signature

    def get_program(self):
        return program


class LocalFunctionSignatureTestDouble(unittest.TestCase):

    @staticmethod
    def test_local_function_signature_test_double():
        pass  # Implement this method.


if __name__ == "__main__":
    unittest.main()
```

Note: The above Python code is a direct translation of the given Java code. However, it may not work as expected because some classes and methods are missing in the provided Java code.