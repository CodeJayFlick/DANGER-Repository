import unittest


class FunctionDefinitionDBTest(unittest.TestCase):

    def setUp(self):
        self.program = create_default_program("test", "TOY")
        self.dtm = self.program.get_data_type_manager()
        start_transaction(self.program)
        fdt = DataTypeManagerDataType("test", dtm, None)
        fdt.set_comment("My comments")
        function_dt = resolve(fdt, dtm)
        self.function_dt = function_dt

    def tearDown(self):
        end_transaction(self.program)

    def test_set_arguments(self):
        parameters = self.function_dt.get_arguments()
        self.assertEqual(0, len(parameters))
        add_three_arguments(self.function_dt)
        parameters = self.function_dt.get_arguments()
        self.assertEqual(3, len(parameters))
        self.assertTrue(parameters[0].get_data_type().is_equivalent(ByteDataType()))
        self.assertTrue(parameters[1].get_data_type().is_equivalent(FloatDataType()))
        self.assertTrue(parameters[2].get_data_type().is_equivalent(CharDataType()))
        self.assertEqual(parameters[0].get_name(), "parm1")
        self.assertEqual(parameters[1].get_name(), "parm2")
        self.assertEqual(parameters[2].get_name(), "parm3")
        self.assertEqual(parameters[0].get_comment(), "this is first parm.")
        self.assertEqual(parameters[1].get_comment(), "this is second parm.")
        self.assertEqual(parameters[2].get_comment(), "this is third parm.")

    def add_three_arguments(self, function_dt):
        new_parameters = [ParameterDefinitionImpl("parm1", ByteDataType(), "this is first parm."),
                          ParameterDefinitionImpl("parm2", FloatDataType(), "this is second parm."),
                          ParameterDefinitionImpl("parm3", CharDataType(), "this is third parm.")]
        function_dt.set_arguments(new_parameters)

    def test_set_name(self):
        self.function_dt.set_name("printf")
        self.assertEqual(self.function_dt.get_name(), "printf")

    def test_set_comment(self):
        self.function_dt.set_comment("My test comment.")
        self.assertEqual(self.function_dt.get_comment(), "My test comment.")

    def test_set_return_type(self):
        self.function_dt.set_return_type(DWordDataType())
        self.assertTrue(self.function_dt.get_return_type().is_equivalent(DWordDataType()))

    def test_equals(self):
        fdt = FunctionDefinitionDataType(self.function_dt, self.dtm)
        self.assertEqual(self.function_dt, fdt)

    def test_not_equals(self):
        fdt = FunctionDefinitionDataType(self.function_dt)
        fdt.set_comment("other comments")
        self.assertFalse(self.function_dt.equals(fdt))


if __name__ == "__main__":
    unittest.main()
