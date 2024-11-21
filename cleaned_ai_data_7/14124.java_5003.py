import unittest

class WeekdayTest(unittest.TestCase):

    def test_to_string(self):
        for weekday in Weekday:
            self.assertIsNotNone(str(weekday))
            self.assertEqual(weekday.name().upper(), str(weekday).upper())

if __name__ == '__main__':
    unittest.main()
