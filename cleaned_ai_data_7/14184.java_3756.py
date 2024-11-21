import unittest

class CommanderUnitTest(unittest.TestCase):

    def test_get_unit_extension(self):
        unit = CommanderUnit("CommanderUnitName")

        self.assertIsNone(unit.get_unit_extension("SoldierExtension"))
        self.assertIsNone(unit.get_unit_extension("SergeantExtension"))
        self.assertIsNotNone(unit.get_unit_extension("CommanderExtension"))

if __name__ == '__main__':
    unittest.main()
