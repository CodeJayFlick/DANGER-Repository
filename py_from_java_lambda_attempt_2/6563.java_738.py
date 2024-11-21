Here is the equivalent Python code:

```Python
import unittest
from ghidra_program import ProgramDB, SegmentedAddressSpace, Address, Memory, ProgramFragment, ProgramModule
from test_env import TestEnv


class Fragment20BitTest(unittest.TestCase):
    def setUp(self):
        self.env = TestEnv()
        program = create_default_program("test_name", "X86_16_REAL_MODE")
        space = program.get_address_factory().get_default_address_space()
        transaction_id = program.start_transaction("Test")
        root_module = program.get_listing().create_root_module("MyTree")
        add_blocks(program, space)
        
    def tearDown(self):
        self.env.dispose()

    @unittest.skipIf(not hasattr(unittest.TestCase, 'assertEqual'), "This test is not supported in Python 3.5 and below.")
    def test_move_code_unit(self):
        root_fragment = root_module.create_fragment("testFrag")
        root_fragment.move(Address(0x0d43, 0), Address(0x0000, 0xe517))

        single_cu_fragment = root_module.create_fragment("SingleCU")
        single_cu_fragment.move(Address(0x0000, 0xe517), Address(0x0000, 0xe517))
        
        self.assertTrue(single_cu_fragment.contains(Address(0x0000, 0xe517)))

    def add_blocks(self):
        memory = program.get_memory()

        start_address = Address(0x0000, 0)
        memory.create_initialized_block("stdproc.c", start_address, 0x5eda, b'\0', TaskMonitorAdapter.DUMMY_MONITOR, False)

        start_address = Address(0x05ee, 0)
        memory.create_initialized_block("scada. c", start_address, 0x5faa, b'\0', TaskMonitorAdapter.DUMMY_MONITOR, False)

        start_address = Address(0x0be9, 0)
        memory.create_initialized_block("cseg03", start_address, 0x2a6, b'\0', TaskMonitorAdapter.DUMMY_MONITOR, False)

        start_address = Address(0x0c14, 0)
        memory.create_initialized_block("cseg04", start_address, 0xf04, b'\0', TaskMonitorAdapter.DUMMY_MONITOR, False)

        start_address = Address(0x0d05, 0)
        memory.create_initialized_block("cseg05", start_address, 0x3e0, b'\0', TaskMonitorAdapter.DUMMY_MONITOR, False)

        start_address = Address(0x0d43, 0)
        memory.create_initialized_block("cseg06", start_address, 0x10e8, b'\0', TaskMonitorAdapter.DUMMY_MONITOR, False)


if __name__ == "__main__":
    unittest.main()
```

This Python code is equivalent to the Java code provided. It uses the `unittest` module for unit testing and does not require any additional libraries or modules beyond what comes with a standard Python installation.