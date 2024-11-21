import unittest
from ghidra.app.plugin.core.analysis import MipsPreAnalyzerTest

class TestMIPSPreAnalyzer(unittest.TestCase):

    def setUp(self):
        self.env = None
        self.program = None
        self.context = None
        self.pair_bit_register = None
        self.builder = None

    def testSimplePair(self):
        self.assertTrue("normal pair", not is_pair_set(self.program, self.context, self.pair_bit_register, 0x1000))
        self.assertTrue("normal pair", not is_pair_set(self.program, self.context, self.pair_bit_register, 0x1004))
        self.assertTrue("normal pair", not is_pair_set(self.program, self.context, self.pair_bit_register, 0x1008))
        self.assertTrue("normal pair", not is_pair_set(self.program, self.context, self.pair_bit_register, 0x100c))

        self.builder.disassemble(0x1000, 16)

        self.assertTrue("normal pair", is_pair_set(self.program, self.context, self.pair_bit_register, 0x1000))
        self.assertTrue("normal pair", is_pair_set(self.program, self.context, self.pair_bit_register, 0x1004))
        self.assertTrue("normal pair", is_pair_set(self.program, self.context, self.pair_bit_register, 0x1008))
        self.assertTrue("normal pair", is_pair_set(self.program, self.context, self.pair_bit_register, 0x100c))

    def testReorderedPair(self):
        self.assertTrue("reordered pair", not is_pair_set(self.program, self.context, self.pair_bit_register, 0x1100))
        self.assertTrue("reordered pair", not is_pair_set(self.program, self.context, self.pair_bit_register, 0x110c))

        self.builder.disassemble(0x1100, 16)

        self.assertTrue("reordered pair", is_pair_set(self.program, self.context, self.pair_bit_register, 0x1100))
        self.assertTrue("reordered pair", is_pair_set(self.program, self.context, self.pair_bit_register, 0x110c))

    def testDelaySlotPair(self):
        self.assertTrue("delay slot pair", not is_pair_set(self.program, self.context, self.pair_bit_register, 0x1200))
        self.assertTrue("delay slot pair", not is_pair_set(self.program, self.context, self.pair_bit_register, 0x1208))

        self.builder.disassemble(0x1200, 12)

        self.assertTrue("delay slot pair", is_pair_set(self.program, self.context, self.pair_bit_register, 0x1200))
        self.assertTrue("delay slot pair", is_pair_set(self.program, self.context, self.pair_bit_register, 0x1208))

    def testMovedPair(self):
        self.assertTrue("moved pair", not is_pair_set(self.program, self.context, self.pair_bit_register, 0x1300))
        self.assertTrue("moved pair", not is_pair_set(self.program, self.context, self.pair_bit_register, 0x130c))

        self.builder.disassemble(0x1300, 16)

        self.assertTrue("moved pair", is_pair_set(self.program, self.context, self.pair_bit_register, 0x1300))
        self.assertTrue("moved pair", is_pair_set(self.program, self.context, self.pair_bit_register, 0x130c))

    def testSeparatedPair(self):
        self.assertTrue("separated pair", not is_pair_set(self.program, self.context, self.pair_bit_register, 0x1500))
        self.assertTrue("separated pair", not is_pair_set(self.program, self.context, self.pair_bit_register, 0x1510))

        set = AddressSet()
        set.add(addr("0x1500"), addr("0x1508"))
        set.add(addr("0x1510"), addr("0x1514"))

        self.builder.disassemble(set)

        self.assertTrue("separated pair", is_pair_set(self.program, self.context, self.pair_bit_register, 0x1500))
        self.assertTrue("separated pair", is_pair_set(self.program, self.context, self.pair_bit_register, 0x1510))

    def test_is_pair_set(self):
        return lambda prog, pc, pbr, addr_off: not bool(pc.getRegisterValue(pbr, Address(addr_off)).getUnsignedValue().intValue())

if __name__ == "__main__":
    unittest.main()
