import unittest
from hamcrest import assert_that, instance_of, not_

class ThiefTest(unittest.TestCase):

    def test_thief(self):
        thief = Thief()
        assert_that(thief, not_(instance_of(Permission)))

if __name__ == '__main__':
    unittest.main()
