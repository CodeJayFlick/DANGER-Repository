import unittest

class TheSwordOfAragornTest(unittest.TestCase):
    def test_basic_sword_test(self):
        sword = SwordOfAragorn()
        self.assertIsNotNone(sword.name)
        self.assertIsNone(sword.locker)
        self.assertFalse(sword.is_locked())
        human = Human("Tupac")
        self.assertTrue(human.acquire(sword))
        self.assertEqual(human, sword.locker)
        self.assertTrue(sword.is_locked())

    def test_invalid_locker_test(self):
        sword = SwordOfAragorn()
        with self.assertRaises(NullPointerException):
            sword.lock(None)
        with self.assertRaises(NullPointerException):
            sword.unlock(None)

if __name__ == '__main__':
    unittest.main()
