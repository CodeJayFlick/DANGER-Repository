import unittest
from ghidra_trace_database_language import DBTraceLanguageManagerTest
from ghidra_program_model_address import AddressOverflowException
from ghidra_test_abstract_g_hidra_headless_integration_test import AbstractGhidraHeadlessIntegrationTest

class TestDBTraceLanguageManager(unittest.TestCase):

    def setUp(self):
        self.b = ToyDBTraceBuilder("Testing", "Toy:BE:64:default")
        self.manager = self.b.trace.get_language_manager()

    def tearDown(self):
        self.b.close()

    @unittest.skip
    def test_get_base_language(self):
        self.assertEqual("Toy:BE:64:default",
                         self.manager.get_base_language().get_language_id().id_as_string)

    @unittest.skip
    def test_add_guest_langauge(self):
        try:
            with UndoableTransaction() as tid:
                self.manager.add_guest_language(self.b.get_language("x86:LE:32:default"))
                self.assertEqual(1, self.manager.language_store.get_record_count())
        except LanguageNotFoundException:
            pass

    @unittest.skip
    def test_get_guest_languages(self):
        try:
            with UndoableTransaction() as tid:
                guest = self.manager.add_guest_language(
                    self.b.get_language("x86:LE:32:default"))
        finally:
            self.assertEqual({guest}, set(self.manager.get_guest_languages()))

    @unittest.skip
    def test_add_mapped_range_then_undo(self):
        try:
            with UndoableTransaction() as tid:
                guest = self.manager.add_guest_language(
                    self.b.get_language("x86:LE:32:default"))
                guest.add_mapped_range(b.addr(0x01000000), b.addr(guest, 0x02000000), 0x1000)
        finally:
            self.b.trace.undo()

    @unittest.skip
    def test_add_mapped_range_then_save_and_load(self):
        try:
            with UndoableTransaction() as tid:
                guest = self.manager.add_guest_language(
                    self.b.get_language("x86:LE:32:default"))
                guest.add_mapped_range(b.addr(0x01000000), b.addr(guest, 0x02000000), 0x1000)
        finally:
            file_saved = self.b.save()
            try:
                with ToyDBTraceBuilder(file_saved) as r:
                    guest_languages = r.trace.get_language_manager().get_guest_languages()
                    self.assertEqual(1, len(guest_languages))
                    self.assertEqual("x86:LE:32:default",
                                     guest_languages[0].get_language().get_language_id().id_as_string)
            except VersionException:
                pass

    @unittest.skip
    def test_delete_mapped_range(self):
        try:
            with UndoableTransaction() as tid:
                guest = self.manager.add_guest_language(
                    self.b.get_language("x86:LE:32:default"))
                range = guest.add_mapped_range(b.addr(0x01000000), b.addr(guest, 0x02000000), 0x1000)
        finally:
            with UndoableTransaction() as tid:
                range.delete(ConsoleTaskMonitor())
                self.assertEqual(set(), set(self.manager.get_guest_languages()))

    @unittest.skip
    def test_delete_mapped_range_then_undo(self):
        try:
            with UndoableTransaction() as tid:
                guest = self.manager.add_guest_language(
                    self.b.get_language("x86:LE:32:default"))
                range = guest.add_mapped_range(b.addr(0x01000000), b.addr(guest, 0x02000000), 0x1000)
        finally:
            with UndoableTransaction() as tid:
                range.delete(ConsoleTaskMonitor())
            self.b.trace.undo()

    @unittest.skip
    def test_delete_guest_language(self):
        try:
            with UndoableTransaction() as tid:
                guest = self.manager.add_guest_language(
                    self.b.get_language("x86:LE:32:default"))
                guest.add_mapped_range(b.addr(0x01000000), b.addr(guest, 0x02000000), 0x1000)
        finally:
            with UndoableTransaction() as tid:
                guest.delete(ConsoleTaskMonitor())
                self.assertEqual(set(), set(self.manager.get_guest_languages()))

    @unittest.skip
    def test_delete_guest_language_then_undo(self):
        try:
            with UndoableTransaction() as tid:
                guest = self.manager.add_guest_language(
                    self.b.get_language("x86:LE:32:default"))
                guest.add_mapped_range(b.addr(0x01000000), b.addr(guest, 0x02000000), 0x1000)
        finally:
            with UndoableTransaction() as tid:
                guest.delete(ConsoleTaskMonitor())
            self.b.trace.undo()

    @unittest.skip
    def test_map_host_to_guest(self):
        try:
            with UndoableTransaction() as tid:
                guest = self.manager.add_guest_language(
                    self.b.get_language("x86:LE:32:default"))
                range = guest.add_mapped_range(b.addr(0x01000000), b.addr(guest, 0x02000000), 0x1000)
        finally:
            with UndoableTransaction() as tid:
                self.assertEqual(None,
                                 guest.map_host_to_guest(b.addr(0x01000800)))

    @unittest.skip
    def test_map_guest_to_host(self):
        try:
            with UndoableTransaction() as tid:
                guest = self.manager.add_guest_language(
                    self.b.get_language("x86:LE:32:default"))
                range = guest.add_mapped_range(b.addr(0x01000000), b.addr(guest, 0x02000000), 0x1000)
        finally:
            with UndoableTransaction() as tid:
                self.assertEqual(None,
                                 guest.map_guest_to_host(b.addr(guest, 0x02000800)))

    @unittest.skip
    def test_add_mapped_range_then_save_and_load(self):
        try:
            with UndoableTransaction() as tid:
                guest = self.manager.add_guest_language(
                    self.b.get_language("x86:LE:32:default"))
                range = guest.add_mapped_range(b.addr(0x01000000), b.addr(guest, 0x02000000), 0x1000)
        finally:
            file_saved = self.b.save()
            try:
                with ToyDBTraceBuilder(file_saved) as r:
                    guest_languages = r.trace.get_language_manager().get_guest_languages()
                    self.assertEqual(1, len(guest_languages))
                    self.assertEqual("x86:LE:32:default",
                                     guest_languages[0].get_language().get_language_id().id_as_string)
            except VersionException:
                pass

    @unittest.skip
    def test_mapped_range_get_host_language(self):
        try:
            with UndoableTransaction() as tid:
                guest = self.manager.add_guest_language(
                    self.b.get_language("x86:LE:32:default"))
                range = guest.add_mapped_range(b.addr(0x01000000), b.addr(guest, 0x02000000), 0x1000)
        finally:
            with UndoableTransaction() as tid:
                self.assertEqual("Toy:BE:64:default",
                                 range.get_host_language().get_language_id().id_as_string)

    @unittest.skip
    def test_mapped_range_get_guest_language(self):
        try:
            with UndoableTransaction() as tid:
                guest = self.manager.add_guest_language(
                    self.b.get_language("x86:LE:32:default"))
                range = guest.add_mapped_range(b.addr(0x01000000), b.addr(guest, 0x02000000), 0x1000)
        finally:
            with UndoableTransaction() as tid:
                self.assertEqual("x86:LE:32:default",
                                 range.get_guest_language().get_language_id().id_as_string)

    @unittest.skip
    def test_mapped_range_get_host_range(self):
        try:
            with UndoableTransaction() as tid:
                guest = self.manager.add_guest_language(
                    self.b.get_language("x86:LE:32:default"))
                range = guest.add_mapped_range(b.addr(0x01000000), b.addr(guest, 0x02000000), 0x1000)
        finally:
            with UndoableTransaction() as tid:
                self.assertEqual(b.range(0x01000000, 0x01000fff),
                                 range.get_host_range())

    @unittest.skip
    def test_mapped_range_get_guest_range(self):
        try:
            with UndoableTransaction() as tid:
                guest = self.manager.add_guest_language(
                    self.b.get_language("x86:LE:32:default"))
                range = guest.add_mapped_range(b.addr(0x01000000), b.addr(guest, 0x02000000), 0x1000)
        finally:
            with UndoableTransaction() as tid:
                self.assertEqual(b.range(guest, 0x02000000, 0x02000fff),
                                 range.get_guest_range())

    @unittest.skip
    def test_delete_mapped_range_then_undo(self):
        try:
            with UndoableTransaction() as tid:
                guest = self.manager.add_guest_language(
                    self.b.get_language("x86:LE:32:default"))
                range = guest.add_mapped_range(b.addr(0x01000000), b.addr(guest, 0x02000000), 0x1000)
        finally:
            with UndoableTransaction() as tid:
                range.delete(ConsoleTaskMonitor())
            self.b.trace.undo()

    @unittest.skip
    def test_delete_guest_language_then_undo(self):
        try:
            with UndoableTransaction() as tid:
                guest = self.manager.add_guest_language(
                    self.b.get_language("x86:LE:32:default"))
                guest.add_mapped_range(b.addr(0x01000000), b.addr(guest, 0x02000000), 0x1000)
        finally:
            with UndoableTransaction() as tid:
                guest.delete(ConsoleTaskMonitor())
            self.b.trace.undo()

    @unittest.skip
    def test_delete_guest_language(self):
        try:
            with UndoableTransaction() as tid:
                guest = self.manager.add_guest_language(
                    self.b.get_language("x86:LE:32:default"))
                guest.add_mapped_range(b.addr(0x01000000), b(addr(guest, 0x02000000), 0x1000)
        finally:
            with UndoableTransaction() as tid:
                guest.delete(ConsoleTaskMonitor())
                self.assertEqual(set(), set(self.manager.get_guest_languages()))

    @unittest.skip
    def test_delete_mapped_range_then_undo(self):
        try:
            with UndoableTransaction() as tid:
                guest = self.manager.add_guest_language(
                    self.b.get_language("x86:LE:32:default"))
                range = guest.add_mapped_range(b.addr(0x01000000), b(addr(guest, 0x02000000), 0x1000)
        finally:
            with UndoableTransaction() as tid:
                range.delete(ConsoleTaskMonitor())
            self.b.trace.undo()

    @unittest.skip
    def test_add_guest_language_then_undo(self):
        try:
            with UndoableTransaction() as tid:
                guest = self.manager.add_guest_language(
                    self.b.get_language("x86:LE:32:default"))
        finally:
            self.b.trace.undo()
