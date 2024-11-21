import unittest
from collections import defaultdict

class DataGatheringParamsTest(unittest.TestCase):

    def test_null_string(self):
        context_regs = DataGatheringParams().get_context_register_list(None)
        self.assertEqual(context_regs, [])

    def test_empty_string(self):
        context_regs = DataGatheringParams().get_context_register_list("")
        self.assertEqual(context_regs, [])

    def test_literal_null(self):
        context_regs = DataGatheringParams().get_context_register_list("null")
        self.assertEqual(context_regs, [])

    def basic_test(self):
        context_regs = DataGatheringParams().get_context_register_list("reg1,reg2,reg3")
        reg_set = set(context_regs)
        self.assertEqual(len(reg_set), 3)
        self.assertIn("reg1", reg_set)
        self.assertIn("reg2", reg_set)
        self.assertIn("reg3", reg_set)

    def test_empty_reg_name(self):
        context_regs = DataGatheringParams().get_context_register_list("reg1, ,reg2")
        reg_set = set(context_regs)
        self.assertEqual(len(reg_set), 2)
        self.assertIn("reg1", reg_set)
        self.assertIn("reg2", reg_set)

    def test_name_trimming(self):
        context_regs = DataGatheringParams().get_context_register_list(" reg1, reg2 ,reg3 ")
        reg_set = set(context_regs)
        self.assertEqual(len(reg_set), 3)
        self.assertIn("reg1", reg_set)
        self.assertIn("reg2", reg_set)
        self.assertIn("reg3", reg_set)

if __name__ == '__main__':
    unittest.main()
