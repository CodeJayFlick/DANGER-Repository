import unittest
from datetime import timedelta, timezone
from pytz import UTC

class GroupByMonthFilterTest(unittest.TestCase):
    MS_TO_DAY = 86400 * 1000
    MS_TO_MONTH = 30 * MS_TO_DAY
    END_TIME = 31507199000

    def test_satisfy1(self):
        filter = self.create_filter(MS_TO_MONTH, 2 * MS_TO_MONTH)
        self.assertTrue(filter.satisfy(0))
        self.assertTrue(filter.satisfy(2678399000))
        self.assertFalse(filter.satisfy(2678400000))
        self.assertFalse(filter.satisfy(5097599000))
        self.assertTrue(filter.satisfy(5097600000))
        self.assertFalse(filter.satisfy(8092800000))
        self.assertFalse(filter.satisfy(15638399000))
        self.assertTrue(filter.satisfy(28828799000))
        self.assertFalse(filter.satisfy(31507199000))

    def test_satisfy2(self):
        filter = self.create_filter(MS_TO_MONTH, MS_TO_MONTH)
        self.assertTrue(filter.satisfy(0))
        self.assertTrue(filter.satisfy(2678399000))
        self.assertTrue(filter.satisfy(2678400000))
        self.assertTrue(filter.satisfy(5097599000))
        self.assertTrue(filter.satisfy(5097600000))
        self.assertTrue(filter.satisfy(31363200000))
        self.assertTrue(filter.satisfy(31507198000))

    def test_satisfy3(self):
        filter = self.create_filter(MS_TO_DAY, MS_TO_MONTH)
        self.assertTrue(filter.satisfy(0))
        self.assertTrue(filter.satisfy(86399000))
        self.assertFalse(filter.satisfy(86400000))
        self.assertFalse(filter.satisfy(2678399000))
        self.assertTrue(filter.satisfy(5097600000))
        self.assertTrue(filter.satisfy(28857600000))

    def test_satisfy4(self):
        filter = self.create_filter(MS_TO_MONTH, MS_TO_DAY * 100)
        self.assertTrue(filter.satisfy(0))
        self.assertTrue(filter.satisfy(2678399000))
        self.assertFalse(filter.satisfy(5097600000))
        self.assertTrue(filter.satisfy(10368000000))

    def test_satisfy_start_end_time(self):
        filter = self.create_filter(MS_TO_DAY, MS_TO_MONTH)
        statistics = LongStatistics()
        statistics.set_start_time(0)
        statistics.set_end_time(MS_TO_DAY)
        self.assertTrue(filter.satisfy(statistics))
        statistics.set_start_time(MS_TO_DAY / 2)
        statistics.set_end_time(MS_TO_DAY * 2)
        self.assertTrue(filter.satisfy(statistics))

    def test_contain_start_end_time(self):
        filter = self.create_filter(MS_TO_DAY, MS_TO_MONTH)
        self.assertFalse(filter.contain_start_end_time(0, MS_TO_DAY))
        self.assertTrue(filter.contain_start_end_time(0, MS_TO_DAY - 1000))
        self.assertFalse(filter.contain_start_end_time(2678399000, 2764799000))

    def test_equals(self):
        filter = self.create_filter(MS_TO_DAY, MS_TO_MONTH)
        filter2 = filter.copy()
        self.assertEqual(filter, filter2)
        filter3 = GroupByMonthFilter(MS_TO_MONTH, MS_TO_MONTH, 0, END_TIME, True, True, UTC())
        self.assertNotEqual(filter, filter3)

    def create_filter(self, sliding_step, time_interval):
        return GroupByMonthFilter(sliding_step, time_interval, 0, END_TIME, True, False, timezone("+08:00"))

class LongStatistics:
    def set_start_time(self, start_time):
        pass

    def set_end_time(self, end_time):
        pass
