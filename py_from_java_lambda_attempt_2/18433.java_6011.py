Here is the equivalent Python code:

```Python
class Pair:
    def __init__(self, key, value):
        self.key = key
        self.value = value

    def __eq__(self, other):
        if isinstance(other, Pair) and self.key == other.key and self.value == other.value:
            return True
        elif not isinstance(other, Pair) or (other is None and self.key is None and self.value is None):
            return False
        else:
            return False

    def __str__(self):
        if isinstance(self.key, str):
            key_str = f'"{self.key}"'
        else:
            key_str = str(self.key)
        
        if isinstance(self.value, int) or isinstance(self.value, float):
            value_str = str(self.value)
        elif self.value is None:
            value_str = 'None'
        else:
            raise TypeError("Unsupported type for Pair's value")

        return f'<{key_str},{value_str}>'

import unittest

class TestPair(unittest.TestCase):

    def test_equals_object(self):
        p1 = Pair('a', 123123)
        p2 = Pair('a', 123123)
        self.assertTrue(p1 == p2)
        p1 = Pair('a', None)
        p2 = Pair('a', 123123)
        self.assertFalse(p1 == p2)
        p1 = Pair('a', 123123)
        p2 = Pair('a', None)
        self.assertFalse(p1 == p2)
        p1 = Pair(None, 123123)
        p2 = Pair('a', 123123)
        self.assertFalse(p1 == p2)
        p1 = Pair('a', 123123)
        p2 = Pair(None, 123123)
        self.assertFalse(p1 == p2)
        p1 = Pair(None, 123123)
        p2 = None
        self.assertFalse(p1 == p2)
        p1 = Pair(None, 123123)
        p2 = Pair(None, 123123)
        map = {}
        map[p1] = 1
        self.assertTrue(map.get(p2) is not None)
        self.assertTrue(p1 == p2)
        p1 = Pair('a', None)
        p2 = Pair('a', None)
        self.assertTrue(p1 == p2)
        self.assertTrue(p1 == p1)
        self.assertFalse(p1 == 123)

    def test_to_string(self):
        p1 = Pair('a', 123123)
        self.assertEqual('<"a",123123>', str(p1))
        p2 = Pair(32.5, 123.123)
        self.assertEqual('<32.5,123.123>', str(p2))

if __name__ == '__main__':
    unittest.main()
```