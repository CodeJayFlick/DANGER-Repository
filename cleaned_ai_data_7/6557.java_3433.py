import unittest
from ghidra.program.database.map import AddressRangeMapDB
from ghidra.program.model.address import AddressImpl
from ghidra.util.exception import CancelledException

class TestAddressRangeMapDB(unittest.TestCase):

    def setUp(self):
        self.env = None  # needed to discover languages
        self.program = None
        self.addr_map = None
        self.space = None

    def tearDown(self):
        if self.program is not None:
            self.program.release()
        self.addr_map = None
        self.env.dispose()

    @unittest.skip("Not implemented")
    def test_transaction(self):

        map = AddressRangeMapDB(self.program.get_db_handle(), self.addr_map, "Test", self)
        try:
            map.paint_range(addr(0), addr(0x1000), 1)  # ONE
            assert False, "expected no-transaction exception"
        except NoTransactionException:
            pass

        id = self.program.start_transaction("TEST")
        try:
            map.paint_range(addr(800), addr(0x1000), 2)  # TWO
            assert False, "expected no-transaction exception"
        except NoTransactionException:
            pass
        finally:
            self.program.end_transaction(id, True)

    @unittest.skip("Not implemented")
    def test_paint(self):

        map = AddressRangeMapDB(self.program.get_db_handle(), self.addr_map, "Test", self)
        id = self.program.start_transaction("TEST")

        try:
            assert map.get_value(addr(0x01000000000L)) is None

            map.paint_range(addr(0x0000001000L), addr(0x0200001000L), 1)  # ONE
            assert map.get_value(addr(0x0000000000L)) is None
            self.assertEqual(map.get_value(addr(0x00000001000L)), 1)
            self.assertEqual(map.get_value(addr(0x0100001000L)), 1)
            self.assertEqual(map.get_value(addr(0x0200001000L)), 1)

            map.paint_range(addr(0x0100000000L), addr(0x0100001000L), 2)  # TWO
            assert map.get_value(addr(0x0000000000L)) is None
            self.assertEqual(map.get_value(addr(0x0000001000L)), 1)
            self.assertEqual(map.get_value(addr(0x0100000fffL)), 2)
            self.assertEqual(map.get_value(addr(0x0100001000L)), 2)
            self.assertEqual(map.get_value(addr(0x0200001000L)), 1)

            map.paint_range(addr(0x0080000000L), addr(0x0100000fffL), 3)  # THREE
            assert map.get_value(addr(0x0000000000L)) is None
            self.assertEqual(map.get_value(addr(0x0000001000L)), 1)
            self.assertEqual(map.get_value(addr(0x0100000fffL)), 3)
            self.assertEqual(map.get_value(addr(0x0100001000L)), 2)
            self.assertEqual(map.get_value(addr(0x0200001000L)), 1)

        finally:
            self.program.end_transaction(id, True)

    @unittest.skip("Not implemented")
    def test_clear(self):

        map = AddressRangeMapDB(self.program.get_db_handle(), self.addr_map, "Test", self)
        id = self.program.start_transaction("TEST")

        try:
            assert map.get_value(addr(0x01000000000L)) is None

            map.paint_range(addr(0x0000001000L), addr(0x0200001000L), 1)  # ONE
            map.paint_range(addr(0x0100000000L), addr(0x0100001000L), 2)  # TWO
            map.paint_range(addr(0x0080000000L), addr(0x0100000fffL), 3)  # THREE

            map.clear_range(addr(0x0100000000L), addr(0x0100000010L))
            map.clear_range(addr(0x01fffffff0L), addr(0x0200000010L))

            assert map.get_value(addr(0x0000000000L)) is None
            self.assertEqual(map.get_value(addr(0x0000001000L)), 1)
            assert map.get_value(addr(0x0100000000L)) is None
            assert map.get_value(addr(0x0100000010L)) is None
            self.assertEqual(map.get_value(addr(0x0100000011L), 3)
            self.assertEqual(map.get_value(addr(0x0200000011L), 1)

        finally:
            self.program.end_transaction(id, True)

    @unittest.skip("Not implemented")
    def test_address_range_iterator(self):

        map = AddressRangeMapDB(self.program.get_db_handle(), self.addr_map, "Test", self)
        id = self.program.start_transaction("TEST")

        try:
            assert map.get_value(addr(0x01000000000L)) is None

            map.paint_range(addr(0x0000001000L), addr(0x0200001000L), 1)  # ONE
            map.paint_range(addr(0x0100000000L), addr(0x0100001000L), 2)  # TWO
            map.paint_range(addr(0x0080000000L), addr(0x0100000fffL), 3)  # THREE

            map.clear_range(addr(0x0100000000L), addr(0x0100000010L))
            map.clear_range(addr(0x01fffffff0L), addr(0x0200000010L))

        finally:
            self.program.end_transaction(id, True)

        iter = map.get_address_ranges()
        while iter.has_next():
            range = iter.next()

    @unittest.skip("Not implemented")
    def test_move(self):

        map = AddressRangeMapDB(self.program.get_db_handle(), self.addr_map, "Test", self)
        id = self.program.start_transaction("TEST")

        try:
            assert map.get_value(addr(0x01000000000L)) is None

            map.paint_range(addr(0x0000001000L), addr(0x0200001000L), 1)  # ONE
            map.paint_range(addr(0x0100000000L), addr(0x0100001000L), 2)  # TWO
            map.paint_range(addr(0x0080000000L), addr(0x0100000fffL), 3)  # THREE

            try:
                map.move_address_range(addr(0x0100000000L), addr(0x0100001000L), 0x1000, TaskMonitorAdapter.DUMMY_MONITOR)
            except CancelledException:
                self.fail()

        finally:
            self.program.end_transaction(id, True)

if __name__ == '__main__':
    unittest.main()
