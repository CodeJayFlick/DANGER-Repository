import unittest
from ghidra.program.model.address import Address
from ghidra.util.task import TaskMonitor

class ByteMappedMemoryBlockTest(unittest.TestCase):

    def setUp(self):
        self.space = program.getAddressFactory().getDefaultAddressSpace()
        transaction_id = program.startTransaction("Test")
        block = memory.createInitializedBlock("BYTE_BLOCK", space.getAddress(0), 0x100, (byte) 0, TaskMonitor.DUMMY, False)
        memory.setBytes(block.getStart(), bytes.fromhex('00' * 0x100))
        self.transaction_id = transaction_id

    def tearDown(self):
        program.endTransaction(self.transaction_id, True)

    def addr(self, offset):
        return Address(self.space, offset)

    @unittest.skip("Test not implemented")
    def testCreateNewBlock1to1(self):

        byte_mapped_block = memory.createByteMappedBlock("test", self.addr(0x1000), self.addr(0x80), 0x100, False)
        self.assertEqual(0x100, byte_mapped_block.getSize())
        self.assertEqual(self.addr(0x1000), byte_mapped_block.getStart())
        self.assertEqual(self.addr(0x10FF), byte_mapped_block.getEnd())

    @unittest.skip("Test not implemented")
    def testCreateNewBlock1to2(self):

        byte_mapped_block = memory.createByteMappedBlock("test", self.addr(0x1000), self.addr(0x80),
            0x100, ByteMappingScheme(1, 2), False)
        self.assertEqual(0x100, byte_mapped_block.getSize())
        self.assertEqual(self.addr(0x1000), byte_mapped_block.getStart())
        self.assertEqual(self.addr(0x10FF), byte_mapped_block.getEnd())

    @unittest.skip("Test not implemented")
    def testCreateNewBlock2to4(self):

        byte_mapped_block = memory.createByteMappedBlock("test", self.addr(0x1000), self.addr(0x80),
            0x100, ByteMappingScheme(2, 4), False)
        self.assertEqual(0x100, byte_mapped_block.getSize())
        self.assertEqual(self.addr(0x1000), byte_mapped_block.getStart())
        self.assertEqual(self.addr(0x10FF), byte_mapped_block.getEnd())

    @unittest.skip("Test not implemented")
    def testCreateNewBlock2to4Overlay(self):

        byte_mapped_block = memory.createByteMappedBlock("test", self.addr(0x1000), self.addr(0x80),
            0x100, ByteMappingScheme(2, 4), True)
        self.assertTrue(byte_mapped_block.isOverlay())

    @unittest.skip("Test not implemented")
    def testNoUnderlyingMemory(self):

        byte_mapped_block = memory.createByteMappedBlock("BYTE_BLOCK", self.addr(0x1000),
            self.addr(0x1020), 0x10, ByteMappingScheme(1, 1), False)
        newblock = memory.createBlock(byte_mapped_block, "Test", self.addr(0x1040), 0x20)
        try:
            newblock.getByte(self.addr(0x1040))
            assert False
        except MemoryAccessException as e:
            pass

if __name__ == '__main__':
    unittest.main()
