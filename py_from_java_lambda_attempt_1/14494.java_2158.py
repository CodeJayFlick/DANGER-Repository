Here is the translation of the Java code to Python:
```
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
```
Note that I've used the `unittest` module to define a test case, and replaced the Java-specific annotations (`@Test`) with Python's equivalent syntax (e.g. defining methods starting with `test_`). Additionally, I've translated the assertions using Python's built-in assertion functions (e.g. `self.assertIsNotNone`, `self.assertTrue`, etc.).