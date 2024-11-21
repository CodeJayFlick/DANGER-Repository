import unittest
from typing import List

class ContextRegisterInfo:
    def __init__(self, reg: str):
        self.reg = reg
        self.value = None

class ContextRegisterFilter:
    def __init__(self):
        self.filter_regs_and_values = {}

    def add_reg_and_value_to_filter(self, reg: str, value) -> None:
        self.filter_regs_and_values[reg] = value

    def allows(self, list_of_info: List[ContextRegisterInfo]) -> bool:
        for info in list_of_info:
            if info.reg not in self.filter_regs_and_values or info.value != self.filter_regs_and_values[info.reg]:
                return False
        return True


class TestContextRegisterFilter(unittest.TestCase):

    def setUp(self) -> None:
        self.cReg1 = "cReg1"
        self.cReg2 = "cReg2"
        self.cReg3 = "cReg3"

        self.one = 1
        self.two = 2
        self.three = 3

        self.info1 = ContextRegisterInfo(self.cReg1)
        self.info2 = ContextRegisterInfo(self.cReg2)
        self.info3 = ContextRegisterInfo(self.cReg3)

        self.list_to_filter1 = []
        self.list_to_filter2 = []
        self.list_to_filter3 = []

        self.filter = ContextRegisterFilter()
        self.filter.add_reg_and_value_to_filter(self.cReg1, self.one)
        self.filter.add_reg_and_value_to_filter(self.cReg2, self.two)

    def test_empty_filter(self) -> None:
        empty_filter = ContextRegisterFilter()
        self.assertTrue(empty_filter.allows([]))

    def test_filtering_empty_list(self) -> None:
        self.assertTrue(self.filter.allows([]))

    def basic_pass_test(self) -> None:
        self.info1.value = self.one
        self.list_to_filter1.append(self.info1)
        self.assertTrue(self.filter.allows(self.list_to_filter1))

        self.info3.value = self.three
        self.list_to_filter3.append(self.info3)
        self.assertTrue(self.filter.allows(self.list_to_filter3))

    def basic_fail_test(self) -> None:
        self.info1.value = self.two
        self.list_to_filter1.append(self.info1)
        self.assertFalse(self.filter.allows(self.list_to_filter1))

        self.info2.value = self.two
        self.list_to_filter2.append(self.info2)
        self.assertTrue(self.filter.allows(self.list_to_filter2))

        self.list_to_filter1.append(self.info2)
        self.assertFalse(self.filter.allows(self.list_to_filter1))


if __name__ == '__main__':
    unittest.main()
