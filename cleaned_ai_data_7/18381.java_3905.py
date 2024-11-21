import unittest


class DoubleStatistics:
    def __init__(self):
        self.min_value = float('inf')
        self.max_value = -float('inf')
        self.sum_values = 0.0
        self.first_value = None
        self.last_value = None

    def update_stats(self, value):
        if not self.is_empty():
            self.update_max_min(value)
        else:
            self.min_value = value
            self.max_value = value
            self.sum_values = value
            self.first_value = value
            self.last_value = value
        else:
            if value < self.min_value:
                self.min_value = value
            elif value > self.max_value:
                self.max_value = value
            self.sum_values += value

    def update_max_min(self, value):
        if value < self.min_value:
            self.min_value = value
        elif value > self.max_value:
            self.max_value = value

    @property
    def is_empty(self):
        return self.min_value == float('inf')

    @property
    def get_first_value(self):
        return self.first_value

    @get_first_value.setter
    def set_first_value(self, value):
        if not self.is_empty:
            self.first_value = value

    @property
    def get_last_value(self):
        return self.last_value

    @get_last_value.setter
    def set_last_value(self, value):
        if not self.is_empty:
            self.last_value = value

    @property
    def get_min_value(self):
        return self.min_value

    @min_value.setter
    def min_value(self, value):
        pass  # Not implemented in this example

    @property
    def get_max_value(self):
        return self.max_value

    @max_value.setter
    def max_value(self, value):
        pass  # Not implemented in this example

    @property
    def get_sum_double_value(self):
        return self.sum_values


class TestDoubleStatistics(unittest.TestCase):

    def test_update(self):
        double_stats = DoubleStatistics()
        double_stats.update_stats(1.34)
        assert not double_stats.is_empty
        double_stats.update_stats(2.32)
        assert not double_stats.is_empty
        self.assertAlmostEqual(double_stats.get_max_value(), 2.32, places=4)
        self.assertAlmostEqual(double_stats.get_min_value(), 1.34, places=4)
        self.assertAlmostEqual(double_stats.get_sum_double_value(), 3.66, places=4)

    def test_merge(self):
        double_stats1 = DoubleStatistics()
        double_stats1.set_first_value(1.34)
        double_stats1.update_stats(100.13453)
        double_stats2 = DoubleStatistics()
        double_stats2.set_start_time(0)
        double_stats2.set_end_time(5)

        double_stats3 = DoubleStatistics()
        double_stats3.merge_statistics(double_stats1)
        assert not double_stats3.is_empty
        self.assertAlmostEqual(double_stats3.get_max_value(), 100.13453, places=4)
        self.assertAlmostEqual(double_stats3.get_min_value(), 1.34, places=4)
        self.assertAlmostEqual(double_stats3.get_sum_double_value(), 101.46853, places=4)

        double_stats3.merge_statistics(double_stats2)
        self.assertAlmostEqual(double_stats3.get_max_value(), 200.435, places=4)
        self.assertAlmostEqual(double_stats3.get_min_value(), 1.34, places=4)
        self.assertAlmostEqual(double_stats3.get_sum_double_value(), 301.90453, places=4)

    def test_unseq_merge(self):
        double_stats3 = DoubleStatistics()
        double_stats3.set_start_time(0)
        double_stats3.set_end_time(5)
        double_stats1 = DoubleStatistics()
        double_stats1.update_stats(122.34)
        double_stats2 = DoubleStatistics()
        double_stats2.update_stats(125.34)

        double_stats4 = DoubleStatistics()
        double_stats4.merge_statistics(double_stats1)
        self.assertAlmostEqual(double_stats3.get_first_value(), 122.34, places=4)
        self.assertAlmostEqual(double_stats3.get_last_value(), 125.34, places=4)

        double_stats5 = DoubleStatistics()
        double_stats5.update_stats(111.1)
        double_stats3.merge_statistics(double_stats5)
        self.assertAlmostEqual(double_stats3.get_first_value(), 122.34, places=4)
        self.assertAlmostEqual(double_stats3.get_last_value(), 125.34, places=4)


if __name__ == '__main__':
    unittest.main()
