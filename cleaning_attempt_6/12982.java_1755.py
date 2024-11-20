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
