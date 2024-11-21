Here is the translation of the given Java code into Python:

```Python
import unittest
from royalty_object_mother import RoyaltyObjectMother, King, Queen


class TestRoyaltyObjectMother(unittest.TestCase):

    def test_unsuccessful_king_flirt(self):
        sober_unhappy_king = RoyaltyObjectMother.create_sober_unhappy_king()
        flirty_queen = RoyaltyObjectMother.create_flirty_queen()
        sober_unhappy_king.flirt(flirty_queen)
        self.assertFalse(sober_unhappy_king.is_happy())

    def test_queen_is_blocking_flirt_cause_drunk_king(self):
        drunk_unhappy_king = RoyaltyObjectMother.create_drunk_king()
        not_flirty_queen = RoyaltyObjectMother.create_not_flirty_queen()
        drunk_unhappy_king.flirt(not_flirty_queen)
        self.assertFalse(drunk_unhappy_king.is_happy())

    def test_queen_is_blocking_flirt(self):
        sober_happy_king = RoyaltyObjectMother.create_happy_king()
        not_flirty_queen = RoyaltyObjectMother.create_not_flirty_queen()
        sober_happy_king.flirt(not_flirty_queen)
        self.assertFalse(sober_happy_king.is_happy())

    def test_successfull_king_flirt(self):
        sober_happy_king = RoyaltyObjectMother.create_happy_king()
        flirty_queen = RoyaltyObjectMother.create_flirty_queen()
        sober_happy_king.flirt(flirty_queen)
        self.assertTrue(sober_happy_king.is_happy())

    def test_queen_type(self):
        flirty_queen = RoyaltyObjectMother.create_flirty_queen()
        not_flirty_queen = RoyaltyObjectMother.create_not_flirty_queen()
        self.assertEqual(type(flirty_queen), type(Queen()))
        self.assertEqual(type(not_flirty_queen), type(Queen()))

    def test_king_type(self):
        drunk_king = RoyaltyObjectMother.create_drunk_king()
        happy_drunk_king = RoyaltyObjectMother.create_happy_drunk_king()
        happy_king = RoyaltyObjectMother.create_happy_king()
        sober_unhappy_king = RoyaltyObjectMother.create_sober_unhappy_king()
        self.assertEqual(type(drunk_king), type(King()))
        self.assertEqual(type(happy_drunk_king), type(King()))
        self.assertEqual(type(happy_king), type(King()))
        self.assertEqual(type(sober_unhappy_king), type(King()))


if __name__ == '__main__':
    unittest.main()
```

Note: This Python code assumes that the `RoyaltyObjectMother` class and its methods (`create_sober_unhappy_king`, `create_flirty_queen`, etc.) are defined in a separate file or module, which is imported at the top of this script.