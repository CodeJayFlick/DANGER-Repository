Here is the translation of the Java code to Python:
```python
import unittest

class VariableUtilitiesTest(unittest.TestCase):
    def setUp(self):
        language = get_language("Toy:BE:64:default")
        compiler_spec = language.get_default_compiler_spec()
        self.program = ProgramDB("Test", language, compiler_spec)

    @staticmethod
    def get_language(language_name):
        ldef_file = Application().get_module_data_file("Toy", "languages/toy.ldefs")
        if ldef_file:
            language_service = DefaultLanguageService(ldef_file)
            return language_service.get_language(LanguageID(language_name))
        raise LanguageNotFoundException(f"Unsupported test language: {language_name}")

    def test_check_data_type(self):
        dt1 = TypedefDataType("Foo", PointerDataType())  # point size will be 8 in program
        self.assertEqual(4, dt1.length)

        dt2 = VariableUtilities.check_data_type(dt1, False, -1, self.program)
        self.assertEqual(8, dt2.length)

        dt3 = ArrayDataType(PointerDataType(), 5, -1)  # point size will be 8 in program
        self.assertEqual(20, dt3.length)

        dt4 = VariableUtilities.check_data_type(dt3, False, -1, self.program)
        self.assertEqual(40, dt4.length)


if __name__ == "__main__":
    unittest.main()
```
Note that I had to make some assumptions about the Python equivalents of Java classes and methods. For example:

* `package` is not a concept in Python, so I removed it.
* `import static org.junit.Assert.*;` is equivalent to importing specific functions from the `unittest` module using `from unittest import assertEqual`.
* `@Before` and `@Test` are equivalent to defining methods with those names that start with `setUp` and `test_check_data_type`, respectively.
* `ResourceFile` and related classes do not have direct equivalents in Python, so I removed them. If you need to work with files or resources in Python, you can use the built-in `open` function or a library like `pathlib`.
* `LanguageNotFoundException` is equivalent to raising a custom exception using the `raise` statement.
* The rest of the code was translated as closely as possible from Java to Python.