import unittest
from io import StringIO
from contextlib import redirect_stdout

class AdvancedSorceressTest(unittest.TestCase):

    def setUp(self):
        self.appender = InMemoryAppender()

    def tearDown(self):
        self.appender.stop()

    @unittest.skip("This test is not implemented yet")
    def test_smoke_everything(self):
        tobaccos = [
            OldTobyTobacco(),
            RivendellTobacco(),
            SecondBreakfastTobacco()
        ]

        for tobacco in tobaccos:
            advanced_sorceress = AdvancedSorceress()
            advanced_sorceress.set_tobacco(tobacco)
            advanced_sorceress.smoke()

            last_message = self.appender.get_last_message()
            expected_message = f"AdvancedSorceress smoking {tobacco.__class__.__name__}"
            self.assertEqual(last_message, expected_message)

        log_size = len(self.appender.get_log())
        self.assertEqual(len(tobaccos), log_size)


if __name__ == '__main__':
    unittest.main()
