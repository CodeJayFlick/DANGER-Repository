import unittest
from ghidra.program.model.address import Address
from ghidra.program.model.listing import Listing
from ghidra.program.model.mem import Memory
from ghidra.util.task import TaskMonitor

class DefaultDataCacheTest(unittest.TestCase):

    def setUp(self):
        self.builder = ToyProgramBuilder("Test", True, None)
        self.builder.create_memory("B1", "1000", 0x2000)
        self.builder.add_bytes_nop("1000", 4)
        self.program = self.builder.get_program()
        self.space = self.program.getAddressFactory().getDefaultAddressSpace()
        self.listing = self.program.getListing()
        self.mem = self.program.getMemory()
        transaction_id = self.program.start_transaction("Test")
        return

    def tearDown(self):
        self.program.end_transaction(transaction_id, True)
        self.program.release(None)

    @unittest.skip
    def test_default_code_units_get_invalidated(self):

        cu = self.listing.getCodeUnitAt(Address(0x1001))
        assert isinstance(cu, DataDB), "cu is not an instance of DataDB"
        data_db = DataDB(cu)
        assert not data_db.isDefined(), "data db is defined"
        assert not invoke_instance_method("isInvalid", data_db), "data db is valid"

        restricted_set = AddressSet(Address(0x1000), Address(0x1003))
        disassembler = Disassembler(self.program, TaskMonitor.DUMMY, None)
        dis_addrs = disassembler.disassemble(Address(0x1000), restricted_set)

        assert not dis_addrs.isEmpty(), "dis addrs is empty"
        assert not invoke_instance_method("checkIsValid", data_db), "data db is valid"

        self.assertIsNone(self.listing.getCodeUnitAt(Address(0x1001)))

    def addr(self, l):
        return Address(l)
