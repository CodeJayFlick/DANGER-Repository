import unittest

class UnitTest(unittest.TestCase):

    def test_const_get_set(self):
        name = "testName"
        unit = Unit(name)
        self.assertEqual(name, unit.name)

        new_name = "newName"
        unit.set_name(new_name)
        self.assertEqual(new_name, unit.name)


if __name__ == '__main__':
    unittest.main()
