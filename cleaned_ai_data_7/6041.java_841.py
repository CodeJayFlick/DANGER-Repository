import unittest
from ghidra_app_plugin_core_functioncompare import FunctionComparisonPlugin, FunctionComparisonProvider, FunctionComparisonModel
from generic_test_abstractgeneric import AbstractGenericTest
from program_database_programbuilder import ProgramBuilder
from program_model_data_datatype import ByteDataType

class CompareFunctionsTest(AbstractGenericTest):
    def setUp(self):
        self.program1 = ProgramBuilder("TestPgm1", "TOY_BE").getProgram()
        self.program2 = ProgramBuilder("TestPgm2", "TOY64_BE").getProgram()

        self.foo = self.program1.createEmptyFunction("Foo", "10018cf", 10, None)
        self.bar = self.program1.createEmptyFunction("Bar", "100299e", 130, None, self.foo, self.foo, self.foo)
        self.junk = self.program1.createEmptyFunction("Junk", "1002cf5", 15, None, self.foo, self.foo, self.foo, self.foo, self.foo)
        self.stuff = self.program1.createEmptyFunction("Stuff", "1003100", 20, None)

        self.one = self.program2.createEmptyFunction("One", "10017c5", 10, None)
        self.two = self.program2.createEmptyFunction("Two", "1001822", 130, None, self.one, self.one, self.one)
        self.three = self.program2.createEmptyFunction("Three", "1001944", 15, None, self.one, self.one, self.one, self.one, self.one)
        self.four = self.program2.createEmptyFunction("Four", "1002100", 20, None)
        self.five = self.program2.createEmptyFunction("Five", "1002200", 20, None)

    @unittest.skip
    def testSetNoFunctions(self):
        provider = compare(set([self.foo]))
        self.assertIsNone(provider)

    @unittest.skip
    def testSetOneFunction(self):
        provider = compare({self.foo})
        CompareFunctionsTestUtility.checkSourceFunctions(provider, self.foo)
        CompareFunctionsTestUtility.checkTargetFunctions(provider, self.foo, self.foo)

    # ... other tests ...

    def create_test_model(self):
        new_model = FunctionComparisonModel()
        
        c1 = FunctionComparison()
        c1.set_source(self.foo)
        c1.add_target(self.bar)
        c1.add_target(self.two)
        new_model.add_comparison(c1)

        c2 = FunctionComparison()
        c2.set_source(self.bar)
        c2.add_target(self.three)
        c2.add_target(self.four)
        c2.add_target(self.five)
        new_model.add_comparison(c2)

        c3 = FunctionComparison()
        c3.set_source(self.junk)
        c3.add_target(self.stuff)
        new_model.add_comparison(c3)

        return new_model

    def test_get_targets(self):
        targets = self.model.get_target_functions()
        self.assertEqual(6, len(targets))
        self.assertIn(self.bar, targets)
        self.assertIn(self.two, targets)
        self.assertIn(self.three, targets)
        self.assertIn(self.four, targets)
        self.assertIn(self.five, targets)
        self.assertIn(self.stuff, targets)

    def test_get_targets_for_source(self):
        targets = self.model.get_target_functions(self.bar)
        self.assertEqual(3, len(targets))
        self.assertIn(self.three, targets)
        self.assertIn(self.four, targets)
        self.assertIn(self.five, targets)

    # ... other tests ...

if __name__ == "__main__":
    unittest.main()
