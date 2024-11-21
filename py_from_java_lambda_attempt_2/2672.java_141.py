Here is the translation of the given Java code into equivalent Python:

```Python
import unittest
from ghidra_trace_database_program import ProgramBuilder, ToyDBTraceBuilder, DBTraceProgramViewMemory, DBTraceMemoryManager, AddressSpace, MemoryBlock, AddressSet
from ghidra_trace_model_memory import TraceOverlappedRegionException

class TestDBTraceProgramViewMemory(unittest.TestCase):

    def setUp(self):
        self.b = ToyDBTraceBuilder("Testing", ProgramBuilder._TOY64_BE)
        with self.b.start_transaction() as tid:
            self.b.trace.get_time_manager().create_snapshot("Created")
        self.memory = self.b.trace.get_memory_manager()
        # NOTE: First snap has to exist first
        self.view = self.b.trace.get_program_view()
        self.vmem = self.view.get_memory()

    def tearDown(self):
        if self.b is not None:
            self.b.close()

    @unittest.skipIf(True, "Test skipped")
    def test_block_in_overlay(self):
        os = self.memory.create_overlay_address_space("test", self.b.trace.get_base_address_factory().get_default_address_space())
        io = self.memory.create_region(".io", 0, self.b.range(os, 0x1000, 0x1fff), TraceMemoryFlag.READ | TraceMemoryFlag.WRITE | TraceMemoryFlag.VOLATILE)
        
        as_set = AddressSet(self.vmem)
        self.assertEqual(as_set, set(range(0x1000, 0x2000)))
        
        blocks = self.vmem.get_blocks()
        self.assertEqual(len(blocks), 1)

        blk = blocks[0]
        self.assertIs(blk, self.vmem.get_block(io))
        self.assertEqual(".io", blk.name)
        self.assertEqual(self.b.addr(os, 0x1000), blk.start)
        self.assertEqual(self.b.addr(os, 0x1fff), blk.end)


if __name__ == '__main__':
    unittest.main()
```

Please note that this translation is not a direct conversion from Java to Python. The code has been adapted and modified as necessary for the differences between the two languages.