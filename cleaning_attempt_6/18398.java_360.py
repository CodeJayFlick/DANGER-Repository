import unittest


class GroupByFilterTest(unittest.TestCase):

    def setUp(self):
        self.group_by_filter = GroupByFilter(3, 24, 8, 8 + 30 * 24 + 3 + 6)

    def test_statistics_satisfy(self):
        statistics = LongStatistics()
        statistics.set_start_time(0)
        statistics.set_end_time(7)
        self.assertFalse(self.group_by_filter.satisfy(statistics))

        statistics.set_start_time(8 + 30 * 24 + 3 + 6 + 1)
        statistics.set_end_time(8 + 30 * 24 + 3 + 6 + 2)
        self.assertFalse(self.group_by_filter.satisfy(statistics))

        statistics.set_start_time(0)
        statistics.set_end_time(9)
        self.assertTrue(self.group_by_filter.satisfy(statistics))

        statistics.set_start_time(32)
        statistics.set_end_time(34)
        self.assertTrue(self.group_by_filter.satisfy(statistics))

        statistics.set_start_time(32)
        statistics.set_end_time(36)
        self.assertTrue(self.group_by_filter.satisfy(statistics))

        statistics.set_start_time(36)
        statistics.set_end_time(37)
        self.assertFalse(self.group_by_filter.satisfy(statistics))

        statistics.set_start_time(36)
        statistics.set_end_time(55)
        self.assertFalse(self.group_by_filter.satisfy(statistics))

        statistics.set_start_time(35)
        statistics.set_end_time(56)
        self.assertTrue(self.group_by_filter.satisfy(statistics))

        statistics.set_start_time(35)
        statistics.set_end_time(58)
        self.assertTrue(self.group_by_filter.satisfy(statistics))

        statistics.set_start_time(8 + 30 * 24 + 3 + 1)
        statistics.set_end_time(8 + 30 * 24 + 5)
        self.assertFalse(self.group_by_filter.satisfy(statistics))

        statistics.set_start_time(8 + 30 * 24 + 3 + 1)
        statistics.set_end_time(8 + 30 * 24 + 8)
        self.assertFalse(self.group_by_filter.satisfy(statistics))


    def test_satisfy(self):
        self.assertFalse(self.group_by_filter.satisfy(0, None))

        self.assertFalse(self.group_by_filter.satisfy(7, None))

        self.assertFalse(self.group_by_filter.satisfy(12, None))

        self.assertFalse(self.group_by_filter.satisfy(8 + 30 * 24 + 3 + 6, None))

        self.assertTrue(self.group_by_filter.satisfy(8, None))

        self.assertTrue(self.group_by_filter.satisfy(9, None))

        self.assertFalse(self.group_by_filter.satisfy(11, None))


    def test_contain_start_end_time(self):
        self.assertTrue(self.group_by_filter.contain_start_end_time(8, 9))
        self.assertFalse(self.group_by_filter.contain_start_end_time(8, 13))
        self.assertFalse(self.group_by_filter.contain_start_end_time(0, 3))
        self.assertFalse(self.group_by_filter.contain_start_end_time(0, 9))
        self.assertFalse(self.group_by_filter.contain_start_end_time(7, 8 + 30 * 24 + 3 + 6 + 1))
        self.assertFalse(
            self.group_by_filter.contain_start_end_time(8 + 30 * 24 + 3 + 6 + 1, 8 + 30 * 24 + 3 + 6 + 2))


if __name__ == '__main__':
    unittest.main()
