import unittest


class LongStatistics:
    def __init__(self):
        self.min_value = None
        self.max_value = None
        self.sum_double_value = 0.0
        self.first_value = None
        self.last_value = None

    def update_stats(self, value):
        if not hasattr(self, 'min_value') or value < self.min_value:
            self.min_value = value
        if not hasattr(self, 'max_value') or value > self.max_value:
            self.max_value = value
        self.sum_double_value += float(value)
        if not hasattr(self, 'first_value'):
            self.first_value = value
        self.last_value = value

    def get_min_value(self):
        return self.min_value

    def get_max_value(self):
        return self.max_value

    def get_sum_double_value(self):
        return self.sum_double_value

    def get_first_value(self):
        return self.first_value

    def get_last_value(self):
        return self.last_value


class TestLongStatistics(unittest.TestCase):

    def test_update(self):
        long_stats = LongStatistics()
        self.assertTrue(long_stats.min_value is None)
        first_value = -120985402913209
        second_value = 1251465332132513

        long_stats.update_stats(first_value)
        self.assertFalse(long_stats.min_value is None)
        long_stats.update_stats(second_value)
        self.assertFalse(long_stats.min_value is None)

        self.assertEqual(second_value, long_stats.get_max_value())
        self.assertEqual(first_value, long_stats.get_min_value())
        self.assertEqual(first_value, long_stats.get_first_value())
        self.assertAlmostEqual((first_value + second_value), long_stats.get_sum_double_value(), places=0)
        self.assertEqual(second_value, long_stats.get_last_value())

    def test_merge(self):
        long_stats1 = LongStatistics()
        long_stats2 = LongStatistics()

        max1 = 100000000000
        max2 = 200000000000

        long_stats1.update_stats(1)
        long_stats1.update_stats(max1)

        long_stats3 = LongStatistics()
        long_stats3.merge_statistics(long_stats1)
        self.assertFalse(long_stats3.min_value is None)
        self.assertEqual(max1, long_stats3.get_max_value())
        self.assertAlmostEqual((max1 + 1), long_stats3.get_sum_double_value(), places=0)
        self.assertEqual(1, long_stats3.get_min_value())
        self.assertEqual(1, long_stats3.get_first_value())
        self.assertEqual(max1, long_stats3.get_last_value())

        long_stats2.update_stats(max2)

        long_stats3.merge_statistics(long_stats2)
        self.assertEqual(max2, long_stats3.get_max_value())
        self.assertAlmostEqual((max2 + max1 + 1), long_stats3.get_sum_double_value(), places=0)
        self.assertEqual(1, long_stats3.get_min_value())
        self.assertEqual(1, long_stats3.get_first_value())
        self.assertEqual(max2, long_stats3.get_last_value())

    def test_merge_mismatch(self):
        int_stats5 = IntegerStatistics()
        int_stats5.update_stats(-10000)

        try:
            long_stats3.merge_statistics(int_stats5)
        except StatisticsClassException as e:
            pass
        else:
            self.fail()

    def test_unseq_merge(self):
        long_stats4 = LongStatistics()
        long_stats5 = LongStatistics()

        max1 = 111

        long_stats4.update_stats(max1)
        long_stats4.update_stats(114)

        long_stats5.update_stats(116)

        long_stats3.merge_statistics(long_stats4)
        self.assertEqual(max1, long_stats3.get_first_value())
        self.assertEqual(114, long_stats3.get_last_value())

        long_stats3.merge_statistics(long_stats5)
        self.assertEqual(max1, long_stats3.get_first_value())
        self.assertEqual(114, long_stats3.get_last_value())


if __name__ == '__main__':
    unittest.main()
