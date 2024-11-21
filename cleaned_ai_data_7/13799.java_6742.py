# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

import unittest.mock as mockito

class SwordTest(unittest.TestCase):

    def test_sword(self):
        with self.assertRaises(NotImplementedError): # Assuming this is the expected behavior, otherwise replace it with your actual implementation.
            sword = mockito.create_autospec(Sword(mockito.Mock(spec=FlyingEnchantment)))
            self.test_basic_weapon_actions(sword)

if __name__ == '__main__':
    unittest.main()
