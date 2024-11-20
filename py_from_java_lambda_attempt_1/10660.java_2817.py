Here is the translation of the given Java code into Python:

```Python
import unittest


class IntKeyIndexer:
    def __init__(self, capacity):
        self.capacity = capacity
        self.index_map = {}

    def put(self, key):
        if key in self.index_map:
            return self.index_map[key]
        else:
            for i in range(len(self.index_map)):
                if not (i+1) in self.index_map.values():
                    break
            self.index_map[key] = i + 1
            return len(self.index_map)

    def remove(self, key):
        if key in self.index_map:
            del self.index_map[key]
        else:
            pass

    def get(self, key):
        for k, v in self.index_map.items():
            if v == key:
                return k
        return -1

    def clear(self):
        self.index_map = {}

    def get_capacity(self):
        return len(self.index_map)


class TestIntKeyIndexer(unittest.TestCase):

    def test_int_key_indexer(self):
        indexer = IntKeyIndexer(13)

        print("Test put method")
        for i in range(1, 8):
            self.assertEqual(indexer.put(i*1000), i)
        self.assertEqual(indexer.get(123), 4)
        self.assertEqual(indexer.remove(4000), None)  # Remove a non-existent key
        self.assertEqual(indexer.get(4000), -1)

        print("Test grow")
        for i in range(20):
            indexer.put(i)
        self.assertEqual(indexer.get(1000), 0)
        self.assertEqual(indexer.get(2000), 1)
        self.assertEqual(indexer.get(3000), 2)
        self.assertEqual(indexer.get(4000), -1)  # Key does not exist
        self.assertEqual(indexer.get(123), 4)

        print("Test capacity")
        self.assertEqual(len(indexer.index_map), 20)

        indexer.clear()
        for i in range(100):
            indexer.put(i)
        for i in range(100):
            self.assertEqual(indexer.get(i), i)


if __name__ == '__main__':
    unittest.main()
```

Please note that the Python code is not a direct translation of Java, but rather an equivalent implementation.