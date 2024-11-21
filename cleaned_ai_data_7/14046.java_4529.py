import unittest
from data_fetcher import DataFetcher


class DirtyFlagTest(unittest.TestCase):

    def test_is_dirty(self):
        df = DataFetcher()
        countries = df.fetch()
        self.assertFalse(countries)

    def test_is_not_dirty(self):
        df = DataFetcher()
        df.fetch()
        countries = df.fetch()
        self.assertTrue(not countries)


if __name__ == '__main__':
    unittest.main()
