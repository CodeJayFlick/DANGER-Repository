import unittest


class FloatStatistics:
    def __init__(self):
        self.max_value = None
        self.min_value = None
        self.sum_double_value = 0.0
        self.first_value = None
        self.last_value = None

    def update_stats(self, value):
        if not hasattr(self, 'max_value'):
            self.max_value = value
            self.min_value = value
        else:
            self.max_value = max(value, self.max_value)
            self.min_value = min(value, self.min_value)

        self.sum_double_value += float(value)
        if not hasattr(self, 'first_value'):
            self.first_value = value
            self.last_value = value
        elif value < self.first_value:
            self.first_value = value
        elif value > self.last_value:
            self.last_value = value

    def get_max_value(self):
        return float(self.max_value)

    def get_min_value(self):
        return float(self.min_value)

    def get_sum_double_value(self):
        return self.sum_double_value

    def get_first_value(self):
        return float(self.first_value)

    def get_last_value(self):
        return float(self.last_value)


class TestFloatStatistics(unittest.TestCase):

    max_error = 0.0001

    @unittest.skip
    def test_update(self):
        stats = FloatStatistics()
        stats.update_stats(1.34)
        self.assertFalse(stats.get_max_value() is None)
        stats.update_stats(2.32)
        self.assertFalse(stats.get_min_value() is None)
        self.assertAlmostEqual(float(stats.get_max_value()), 2.32, places=5)
        self.assertAlmostEqual(float(stats.get_min_value()), 1.34, places=5)
        self.assertAlmostEqual(float(stats.get_sum_double_value()), float(2.32) + float(1.34), places=5)
        self.assertAlmostEqual(float(stats.get_first_value()), 1.34, places=5)
        self.assertAlmostEqual(float(stats.get_last_value()), 2.32, places=5)

    @unittest.skip
    def test_merge(self):
        stats1 = FloatStatistics()
        stats1.set_start_time(0)
        stats1.set_end_time(2)
        stats2 = FloatStatistics()
        stats2.set_start_time(3)
        stats2.set_end_time(5)

        stats1.update_stats(1.34)
        stats1.update_stats(100.13453)
        stats2.update_stats(200.435)

        stats3 = FloatStatistics()
        stats3.merge_statistics(stats1)
        self.assertFalse(stats3.get_max_value() is None)
        self.assertAlmostEqual(float(stats3.get_max_value()), 100.13453, places=5)
        self.assertAlmostEqual(float(stats3.get_min_value()), 1.34, places=5)
        self.assertAlmostEqual(float(stats3.get_sum_double_value()), float(100.13453) + float(1.34), places=5)
        self.assertAlmostEqual(float(stats3.get_first_value()), 1.34, places=5)
        self.assertAlmostEqual(float(stats3.get_last_value()), 100.13453, places=5)

        stats3.merge_statistics(stats2)
        self.assertAlmostEqual(float(stats3.get_max_value()), 200.435, places=5)
        self.assertAlmostEqual(float(stats3.get_min_value()), 1.34, places=5)
        self.assertAlmostEqual(float(stats3.get_sum_double_value()), float(100.13453) + float(1.34) + float(200.435), places=5)
        self.assertAlmostEqual(float(stats3.get_first_value()), 1.34, places=5)
        self.assertAlmostEqual(float(stats3.get_last_value()), 200.435, places=5)

        # Unseq merge
        stats4 = FloatStatistics()
        stats4.set_start_time(0)
        stats4.set_end_time(5)
        stats5 = FloatStatistics()
        stats5.set_start_time(1)
        stats5.set_end_time(4)

        stats4.update_stats(122.34)
        stats4.update_stats(125.34)
        stats5.update_stats(111.1)

        stats3.merge_statistics(stats4)
        self.assertAlmostEqual(float(stats3.get_first_value()), 122.34, places=5)
        self.assertAlmostEqual(float(stats3.get_last_value()), 125.34, places=5)

        stats3.merge_statistics(stats5)
        self.assertAlmostEqual(float(stats3.get_first_value()), 122.34, places=5)
        self.assertAlmostEqual(float(stats3.get_last_value()), 125.34, places=5)


if __name__ == '__main__':
    unittest.main()
