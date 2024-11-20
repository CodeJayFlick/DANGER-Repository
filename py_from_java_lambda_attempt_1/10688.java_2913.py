Here is the equivalent Python code:

```Python
import unittest
from weakref import WeakValueDictionary as WeakValueHashMap

class Foo:
    def __init__(self, name):
        self.name = name

    def get_name(self):
        return self.name


class TestWeakValueHashMap(unittest.TestCase):

    def test_map1(self):
        cache = WeakValueHashMap()
        cache[0] = Foo("AAA")
        cache[1] = Foo("BBB")
        cache[2] = Foo("CCC")

        self.assertEqual(len(cache), 3)

        self.assertEqual(cache[0].get_name(), "AAA")
        self.assertEqual(cache[1].get_name(), "BBB")
        self.assertEqual(cache[2].get_name(), "CCC")

        for _ in range(100):
            import gc
            gc.collect()
            import time
            time.sleep(0.01)
            cache.get(0)
            if len(cache) == 0:
                break

        self.assertEqual(len(cache), 0)


if __name__ == '__main__':
    unittest.main()
```

Note that Python does not have a direct equivalent to Java's `WeakValueHashMap`. Instead, we use the built-in `weakref` module and its `WeakValueDictionary` class.