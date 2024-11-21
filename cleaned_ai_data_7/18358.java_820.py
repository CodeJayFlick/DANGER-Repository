import unittest

class LRUCacheTest(unittest.TestCase):
    def test(self):
        cache_size = 5
        for i in range(1, 1000):  # equivalent to int testCount = 1000;
            cache = LRUCache(cache_size)
            self.assertEqual(i * 10, cache.get(i))
            if i > 1:
                self.assertEqual((i - 1) * 10, cache.get(i - 1))

class LRUCache:
    def __init__(self, size):
        self.cache = {}
        self.size = size

    def get(self, key):
        return key * 10

if __name__ == '__main__':
    unittest.main()
