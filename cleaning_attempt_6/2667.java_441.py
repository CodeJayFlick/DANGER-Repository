import unittest
from ghidra_trace_database_module import ToyDBTraceBuilder, DBTraceModuleManager, TraceModule, TraceSection


class TestDBTraceModuleManager(unittest.TestCase):

    def setUp(self):
        self.b = ToyDBTraceBuilder("Testing", "Toy:BE:64:default")
        self.module_manager = self.b.trace.get_module_manager()

    def tearDown(self):
        self.b.close()

    @unittest.skip
    def test_add_module(self):
        with self.b.start_transaction() as tid:
            self.module_manager.add_module("first", "first", range(0x00400000, 0x0060002f), Range.closed(0L, 10L))
            self.module_manager.add_loaded_module("second", "second", range(0x7f400000, 0x7f60002f), 0)

    @unittest.skip
    def test_add_sections(self):
        with self.b.start_transaction() as tid:
            mod1 = self.module_manager.add_module("first", "first", range(0x00400000, 0x0060002f), Range.closed(0L, 10L))
            mod1.add_section(".text", range(0x00401000, 0x00401f9f))
            mod1.add_section(".data", range(0x00600000, 0x0060002f))

    @unittest.skip
    def test_get_all_modules(self):
        self.assertEqual(set(), set(self.module_manager.get_all_modules()))

        with self.b.start_transaction() as tid:
            mod1 = self.module_manager.add_module("first", "first", range(0x00400000, 0x0060002f), Range.closed(0L, 10L))
            mod1.add_section(".text", range(0x00401000, 0x00401f9f))
            mod1.add_section(".data", range(0x00600000, 0x0060002f))

        self.assertEqual({mod1}, set(self.module_manager.get_all_modules()))

    @unittest.skip
    def test_get_modules_by_path(self):
        self.assertEqual(set(), set(self.module_manager.get_modules_by_path("first")))

        with self.b.start_transaction() as tid:
            mod1 = self.module_manager.add_module("first", "first", range(0x00400000, 0x0060002f), Range.closed(0L, 10L))
            mod1.add_section(".text", range(0x00401000, 0x00401f9f))
            mod1.add_section(".data", range(0x00600000, 0x0060002f))

        self.assertEqual({mod1}, set(self.module_manager.get_modules_by_path("first")))

    @unittest.skip
    def test_module_get_trace(self):
        with self.b.start_transaction() as tid:
            mod1 = self.module_manager.add_module("first", "first", range(0x00400000, 0x0060002f), Range.closed(0L, 10L))

        self.assertEqual(self.b.trace, mod1.get_trace())

    @unittest.skip
    def test_module_set_get_name(self):
        with self.b.start_transaction() as tid:
            mod1 = self.module_manager.add_module("first", "first", range(0x00400000, 0x0060002f), Range.closed(0L, 10L))

        self.assertEqual("first", mod1.get_name())

        mod1.set_name("FIRST")
        self.assertEqual("FIRST", mod1.get_name())

    @unittest.skip
    def test_module_set_get_base(self):
        with self.b.start_transaction() as tid:
            mod1 = self.module_manager.add_module("first", "first", range(0x00400000, 0x0060002f), Range.closed(0L, 10L))

        self.assertEqual(self.b.addr(0x00400000), mod1.get_base())

        mod1.set_base(self.b.addr(0x00400100))
        self.assertEqual(self.b.addr(0x00400100), mod1.get_base())

    @unittest.skip
    def test_module_set_get_lifespan(self):
        with self.b.start_transaction() as tid:
            mod1 = self.module_manager.add_module("first", "first", range(0x00400000, 0x0060002f), Range.closed(0L, 10L))

        self.assertEqual(Range.closed(0L, 10L), mod1.get_lifespan())

        mod1.set_lifespan(Range.closed(1L, 11L))
        self.assertEqual(Range.closed(1L, 11L), mod1.get_lifespan())

    @unittest.skip
    def test_module_delete(self):
        with self.b.start_transaction() as tid:
            mod1 = self.module_manager.add_module("first", "first", range(0x00400000, 0x0060002f), Range.closed(0L, 10L))
            mod1.add_section(".text", range(0x00401000, 0x00401f9f))
            mod1.add_section(".data", range(0x00600000, 0x0060002f))

        with self.b.start_transaction() as tid:
            mod1.delete()

    @unittest.skip
    def test_section_get_module(self):
        with self.b.start_transaction() as tid:
            mod1 = self.module_manager.add_module("first", "first", range(0x00400000, 0x0060002f), Range.closed(0L, 10L))
            s1text = mod1.add_section(".text", range(0x00401000, 0x00401f9f))

        self.assertEqual(mod1, s1text.get_module())

    @unittest.skip
    def test_section_set_get_name(self):
        with self.b.start_transaction() as tid:
            mod1 = self.module_manager.add_module("first", "first", range(0x00400000, 0x0060002f), Range.closed(0L, 10L))
            s1text = mod1.add_section(".text", ".text")

        self.assertEqual(".text", s1text.get_name())

        s1text.set_name("_TEXT")
        self.assertEqual("_TEXT", s1text.get_name())

    @unittest.skip
    def test_section_get_range(self):
        with self.b.start_transaction() as tid:
            mod1 = self.module_manager.add_module("first", "first", range(0x00400000, 0x0060002f), Range.closed(0L, 10L))
            s1text = mod1.add_section(".text", ".text")

        self.assertEqual(self.b.range(0x00401000, 0x00401f9f), s1text.get_range())

    @unittest.skip
    def test_save_then_load(self):
        with self.b.start_transaction() as tid:
            mod1 = self.module_manager.add_module("first", "first", range(0x00400000, 0x0060002f), Range.closed(0L, 10L))
            mod1.add_section(".text", range(0x00401000, 0x00401f9f))
            mod1.add_section(".data", range(0x00600000, 0x0060002f))

        with self.b.start_transaction() as tid:
            mod2 = self.module_manager.add_module("second", "second", range(0x7f400000, 0x7f60002f), Range.closed(1L, 11L))

        tmp = self.b.save()
        try:
            b = ToyDBTraceBuilder(tmp)
            module_manager = b.trace.get_module_manager()

            mod1 = assert_one(module_manager.get_modules_by_path("first"))
            mod2 = assert_one(module_manager.get_modules_by_path("second"))

            s1text = mod1.get_sectionByName(".text")
            s1data = mod1.get_sectionByName(".data")

            self.assertEqual(self.b.addr(0x00400000), mod1.get_base())
            self.assertEqual(Range.closed(0L, 10L), mod1.get_lifespan())
            self.assertEqual(self.b.addr(0x7f400000), mod2.get_base())
            self.assertEqual(Range.closed(1L, 11L), mod2.get_lifespan())

        finally:
            tmp.close()

    @unittest.skip
    def test_undo_then_redo(self):
        with self.b.start_transaction() as tid:
            mod1 = self.module_manager.add_module("first", "first", range(0x00400000, 0x0060002f), Range.closed(0L, 10L))
            mod1.add_section(".text", range(0x00401000, 0x00401f9f))
            mod1.add_section(".data", range(0x00600000, 0x0060002f))

        with self.b.start_transaction() as tid:
            mod2 = self.module_manager.add_module("second", "second", range(0x7f400000, 0x7f60002f), Range.closed(1L, 11L))

        self.b.undo()

        self.assertEqual(set(), set(self.module_manager.get_all_modules()))

        self.b.redo()

        mod1 = assert_one(module_manager.get_modules_by_path("first"))
        mod2 = assert_one(module_manager.get_modules_by_path("second"))

        s1text = mod1.get_sectionByName(".text")
        s1data = mod1.get_sectionByName(".data")

        self.assertEqual(self.b.addr(0x00400000), mod1.get_base())
        self.assertEqual(Range.closed(0L, 10L), mod1.get_lifespan())
        self.assertEqual(self.b.addr(0x7f400000), mod2.get_base())
        self.assertEqual(Range.closed(1L, 11L), mod2.get_lifespan())

    def assert_one(self, col):
        self.assertEqual(1, len(col))
        return list(col)[0]


if __name__ == "__main__":
    unittest.main()
