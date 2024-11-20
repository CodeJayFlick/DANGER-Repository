Here is the translation of the Java code to Python:

```Python
import unittest
from threading import Thread
from time import sleep

class FeindTest(unittest.TestCase):

    def setUp(self):
        self.elf = Elf("Nagdil")
        self.orc = Orc("Ghandar")
        self.sword = SwordOfAragorn()

    def test_null_tests(self):
        with self.assertRaises(NullPointerException):
            Feind(None, None)
        with self.assertRaises(NullPointerException):
            Feind(self.elf, None)
        with self.assertRaises(NullPointerException):
            Feind(None, self.sword)

    def test_base_case(self):
        base = Thread(target=Feind(self.orc, self.sword).run)
        base.start()
        base.join()
        self.assertIsNone(self.sword.get_locker())
        
        extend = Thread(target=Feind(self.elf, self.sword).run)
        extend.start()
        extend.join()
        self.assertTrue(self.sword.is_locked())

        if self.elf.is_alive():
            self.sword.unlock(self.elf)
        else:
            self.sword.unlock(self.orc)

        self.assertIsNone(self.sword.get_locker())


class Elf:
    def __init__(self, name):
        self.name = name
        self.is_alive = True

    @property
    def is_alive(self):
        return self._is_alive

    @is_alive.setter
    def is_alive(self, value):
        if not isinstance(value, bool):
            raise ValueError("Value must be a boolean")
        self._is_alive = value


class Orc:
    def __init__(self, name):
        self.name = name
        self.is_alive = True

    @property
    def is_alive(self):
        return self._is_alive

    @is_alive.setter
    def is_alive(self, value):
        if not isinstance(value, bool):
            raise ValueError("Value must be a boolean")
        self._is_alive = value


class SwordOfAragorn:
    def __init__(self):
        pass

    def unlock(self, entity):
        pass

    @property
    def get_locker(self):
        return None

    @get_locker.setter
    def set_locker(self, entity):
        pass

    @property
    def is_locked(self):
        return False


if __name__ == '__main__':
    unittest.main()
```

Please note that Python does not have a direct equivalent to Java's `@BeforeEach` and `@Test`. Instead, we use the `setUp` method in our test class. Also, I've replaced the `Assertions.assertThrows` with `with self.assertRaises`, which is used to assert if an exception of certain type was raised during execution of code inside this block.