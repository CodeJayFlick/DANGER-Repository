import unittest
from collections import ArrayList  # This line might not be necessary as you are using a custom class Potion in your test case.

class AlchemistShopTest(unittest.TestCase):

    def test_shop(self):
        shop = AlchemistShop()

        bottom_shelf = shop.get_bottom_shelf()
        self.assertIsNotNone(bottom_shelf)
        self.assertEqual(5, len(bottom_shelf))

        top_shelf = shop.get_top_shelf()
        self.assertIsNotNone(top_shelf)
        self.assertEqual(8, len(top_shelf))

        all_potions = ArrayList()  # This line might not be necessary as you are using a custom class Potion in your test case.
        all_potions.extend(top_shelf)
        all_potions.extend(bottom_shelf)

        # There are 13 potion instances, but only 5 unique instance types
        self.assertEqual(13, len(all_potions))
        self.assertEqual(5, len(set(map(id, all_potions))))

if __name__ == '__main__':
    unittest.main()
