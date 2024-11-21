import unittest
from ghidra.program.database.util import SharedRangeMapDB

class TestSharedRangeMapDB(unittest.TestCase):

    def setUp(self):
        self.dbh = DBHandle()
        transactionID = self.dbh.startTransaction()

    def tearDown(self):
        self.dbh.endTransaction(transactionID, False)
        self.dbh.close()

    @unittest.skip("Not implemented")
    def testAdd(self):
        map = SharedRangeMapDB(self.dbh, "TEST", self, True)

        # Add initial set of ranges
        map.add(10, 20, 1)
        map.add(30, 40, 1)
        map.add(50, 60, 1)
        map.add(70, 80, 1)

        ranges = [IndexRange(10, 20), IndexRange(30, 40), IndexRange(50, 60), IndexRange(70, 80)]
        entries = [IndexRange(10, 1), IndexRange(30, 1), IndexRange(50, 1), IndexRange(70, 1)]

        self.inspectRecords(map, ranges, entries)

        # Range already included
        map.add(52, 58, 1)
        map.add(52, 60, 1)
        map.add(50, 60, 1)

        self.inspectRecords(map, ranges, entries)

        # Add range
        map.add(21, 29, 1)

        ranges = [IndexRange(10, 40), IndexRange(50, 60), IndexRange(70, 80)]
        entries = [IndexRange(10, 1), IndexRange(50, 1), IndexRange(70, 1)]

        self.inspectRecords(map, ranges, entries)

        # Add range
        map.add(35, 55, 1)

        ranges = [IndexRange(10, 60), IndexRange(70, 80)]
        entries = [IndexRange(10, 1), IndexRange(70, 1)]

        self.inspectRecords(map, ranges, entries)

        # Add range
        map.add(55, 90, 1)

        ranges = [IndexRange(10, 90)]
        entries = [IndexRange(10, 1)]

        self.inspectRecords(map, ranges, entries)

        # Add second overlapped value
        map.add(20, 30, 2)

        ranges = [IndexRange(10, 19), IndexRange(20, 27), IndexRange(28, 30), IndexRange(31, 90)]
        entries = [IndexRange(10, 1), IndexRange(20, 1), IndexRange(28, 1), IndexRange(31, 1)]

        self.inspectRecords(map, ranges, entries)

        # Add third overlapped value
        map.add(28, 35, 3)

        ranges = [IndexRange(10, 19), IndexRange(20, 27), IndexRange(28, 30), IndexRange(31, 35), IndexRange(36, 90)]
        entries = [IndexRange(10, 1), IndexRange(20, 1), IndexRange(25, 2), IndexRange(28, 3)]

        self.inspectRecords(map, ranges, entries)

        # Add fourth overlapped value
        map.add(28, 35, 4)

        ranges = [IndexRange(10, 19), IndexRange(20, 27), IndexRange(28, 30), IndexRange(31, 35), IndexRange(36, 90)]
        entries = [IndexRange(10, 1), IndexRange(20, 2), IndexRange(25, 4)]

        self.inspectRecords(map, ranges, entries)

    @unittest.skip("Not implemented")
    def testRemove(self):
        map = SharedRangeMapDB(self.dbh, "TEST", self, True)

        # Add same entries as the testAdd used
        map.add(10, 20, 1)
        map.add(30, 40, 1)
        map.add(50, 60, 1)
        map.add(70, 80, 1)

        map.add(21, 29, 1)

        map.add(35, 55, 1)

        map.add(55, 90, 1)

        map.add(20, 30, 2)

        map.add(28, 35, 3)

        map.add(28, 35, 4)

        # Remove
        map.remove(4)
        self.assertEqual(map.rangeTable.getRecordCount(), 0)
        self.assertEqual(map.mapTable.getRecordCount(), 0)

    @unittest.skip("Not implemented")
    def testGetValueIterator(self):
        map = SharedRangeMapDB(self.dbh, "TEST", self, True)

        # Add same entries as the testAdd used
        map.add(10, 20, 1)
        map.add(30, 40, 1)
        map.add(50, 60, 1)
        map.add(70, 80, 1)

        map.add(21, 29, 1)

        map.add(35, 55, 1)

        map.add(55, 90, 1)

        map.add(20, 30, 2)

        map.add(28, 35, 3)

        map.add(28, 35, 4)
        map.add(25, 39, 4)

        iter = map.getValueIterator(29, 34)
        values = [LongField(1), LongField(2), LongField(3), LongField(4)]
        cnt = 0
        while iter.hasNext():
            ++cnt
            v = (iter.next())
            if not isinstance(v, LongField) or v.getLongValue() in [x.getLongValue() for x in values]:
                self.fail("Unexpected value: " + str(v))

        self.assertEqual(len(values), cnt)

    @unittest.skip("Not implemented")
    def testGetValueRangeIterator(self):
        map = SharedRangeMapDB(self.dbh, "TEST", self, True)
        print("testGetValueRangeIterator ---")

        # Add same entries as the testAdd used
        map.add(10, 20, 1)
        map.add(30, 40, 1)
        map.add(50, 60, 1)
        map.add(70, 80, 1)

        map.add(21, 29, 1)

        map.add(35, 55, 1)

        map.add(55, 90, 1)

        map.add(20, 30, 2)

        map.add(28, 35, 3)
        map.add(25, 39, 4)

        iter = map.getValueRangeIterator(2)
        ranges = [IndexRange(20, 24), IndexRange(25, 27), IndexRange(28, 30)]
        cnt = 0
        while iter.hasNext():
            ++cnt
            range = (iter.next())
            if not isinstance(range, IndexRange) or range.getStart() in [x.getStart() for x in ranges]:
                self.fail("Unexpected range: " + str(range))

        print("  Range:", range.getStart(), "-", range.getEnd())

    def inspectRecords(self, map, ranges, entries):
        recordIterator = map.rangeTable.iterator()
        cnt = 0
        while recordIterator.hasNext():
            ++cnt
            rec = (recordIterator.next())
            if not isinstance(rec, DBRecord) or rec.getKey() in [x.getStart() for x in ranges]:
                self.fail("Unexpected range: " + str(rec))

        self.assertEqual(len(ranges), cnt)

        recordIterator = map.mapTable.iterator()
        cnt = 0
        while recordIterator.hasNext():
            ++cnt
            rec = (recordIterator.next())
            if not isinstance(rec, DBRecord) or rec.getLongValue(SharedRangeMapDB.MAP_RANGE_KEY_COL) in [x.getStart() for x in entries]:
                self.fail("Unexpected map entry: rangeKey=" + str(rec.getLongValue(SharedRangeMapDB.MAP_RANGE_KEY_COL)) + ", value=" + str(rec.getLongValue(SharedRangeMapDB.MAP_VALUE_COL)))

        self.assertEqual(len(entries), cnt)

if __name__ == '__main__':
    unittest.main()
