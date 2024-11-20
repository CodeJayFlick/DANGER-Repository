Here is the translation of the given Java code into Python:

```Python
import unittest

class MinTimeMaxTimeFilterTest(unittest.TestCase):

    min_time = 100
    max_time = 200

    def test_eq(self):
        time_eq = TimeFilter.eq(10)
        self.assertFalse(time_eq.satisfy_start_end_time(min_time, max_time))
        self.assertFalse(time_eq.contain_start_end_time(min_time, max_time))

        time_eq = TimeFilter.eq(100)
        self.assertTrue(time_eq.satisfy_start_end_time(min_time, max_time))
        self.assertTrue(time_eq.contain_start_end_time(min_time, min_time))

        time_eq = TimeFilter.eq(150)
        self.assertTrue(time_eq.satisfy_start_end_time(min_time, max_time))
        self.assertFalse(time_eq.contain_start_end_time(min_time, max_time))

        time_eq = TimeFilter.eq(200)
        self.assertTrue(time_eq.satisfy_start_end_time(min_time, max_time))
        self.assertFalse(time_eq.contain_start_end_time(min_time, max_time))

        time_eq = TimeFilter.eq(300)
        self.assertFalse(time_eq.satisfy_start_end_time(min_time, max_time))
        self.assertFalse(time_eq.contain_start_end_time(min_time, max_time))

    def test_gt(self):
        time_eq = TimeFilter.gt(10)
        self.assertTrue(time_eq.satisfy_start_end_time(min_time, max_time))
        self.assertTrue(time_eq.contain_start_end_time(min_time, max_time))

        time_eq = TimeFilter.gt(100)
        self.assertTrue(time_eq.satisfy_start_end_time(min_time, max_time))
        self.assertFalse(time_eq.contain_start_end_time(min_time, max_time))

        time_eq = TimeFilter.gt(200)
        self.assertFalse(time_eq.satisfy_start_end_time(min_time, max_time))
        self.assertFalse(time_eq.contain_start_end_time(min_time, max_time))

        time_eq = TimeFilter.gt(300)
        self>false(self.time_eq.satisfy_start_end_time(min_time, max_time))
        self>false(self.time_eq.contain_start_end_time(min_time, max_time))

    def test_gteq(self):
        time_eq = TimeFilter.gteq(10)
        self.assertTrue(time_eq.satisfy_start_end_time(min_time, max_time))
        self.assertTrue(time_eq.contain_start_end_time(min_time, max_time))

        time_eq = TimeFilter.gteq(100)
        self.assertTrue(time_eq.satisfy_start_end_time(min_time, max_time))
        self.assertTrue(time_eq.contain_start_end_time(min_time, max_time))

        time_eq = TimeFilter.gteq(200)
        self.assertFalse(time_eq.satisfy_start_end_time(min_time, max_time))
        self>false(self.time_eq.contain_start_end_time(min_time, max_time))

    def test_lt(self):
        time_eq = TimeFilter.lt(10)
        self.assertFalse(time_eq.satisfy_start_end_time(min_time, max_time))
        self>false(self.time_eq.contain_start_end_time(min_time, max_time))

        time_eq = TimeFilter.lt(100)
        self>false(self.time_eq.satisfy_start_end_time(min_time, max_time))
        self>false(self.time_eq.contain_start_end_time(min_time, max_time))

        time_eq = TimeFilter.lt(200)
        self>true(self.time_eq.satisfy_start_end_time(min_time, max_time))
        self>false(self.time_eq.contain_start_end_time(min_time, max_time))

    def test_lteq(self):
        time_eq = TimeFilter.lteq(10)
        self.assertFalse(time_eq.satisfy_start_end_time(min_time, max_time))
        self>false(self.time_eq.contain_start_end_time(min_time, max_time))

        time_eq = TimeFilter.lteq(100)
        self>true(self.time_eq.satisfy_start_end_time(min_time, max_time))
        self>false(self.time_eq.contain_start_end_time(min_time, max_time))

    def test_and(self):
        and_filter = FilterFactory.and(TimeFilter.gt(10), TimeFilter.lt(50))
        self.assertFalse(and_filter.satisfy_start_end_time(min_time, max_time))
        self>false(self.and_filter.contain_start_end_time(min_time, max_time))

        and_filter = FilterFactory.and(TimeFilter.gteq(100), TimeFilter.lteq(200))
        self>true(self.and_filter.satisfy_start_end_time(min_time, max_time))
        self>false(self.and_filter.contain_start_end_time(min_time, max_time))

    def test_or(self):
        or_filter = FilterFactory.or(TimeFilter.gt(10), TimeFilter.lt(50))
        self>true(self.or_filter.satisfy_start_end_time(min_time, max_time))
        self>true(self.or_filter.contain_start_end_time(min_time, max_time))

    def test_not_eq(self):
        time_eq = TimeFilter.noteq(10)
        self.assertTrue(time_eq.satisfy_start_end_time(min_time, max_time))
        self>true(self.time_eq.satisfy_start_end_time(min_time, min_time))

        start_time = 10
        end_time = 10
        self>false(time_eq.satisfy_start_end_time(start_time, end_time))
        self>false(time_eq.contain_start_end_time(5, 50))

    def test_not(self):
        not_filter = FilterFactory.not(TimeFilter.lteq(10))
        self>true(not_filter.satisfy_start_end_time(min_time, max_time))
        self>true(not_filter.contain_start_end_time(min_time, max_time))


if __name__ == '__main__':
    unittest.main()
```

Please note that the Python code does not exactly match with Java code.