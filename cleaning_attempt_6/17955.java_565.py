import unittest


class LRUCacheTest(unittest.TestCase):

    CACHE_SIZE = 3
    DATA_SIZE = CACHE_SIZE << 3

    def setUp(self):
        self.cache = {}

    def test_put_get_randomly(self):
        for i in range(CACHE_SIZE):
            self.cache[i] = i
            assert self.cache.get(i) == i

        self.cache[4] = 4
        assert self.cache.get(0) == 0
        assert self.cache.get(4) == 4

        self.cache[10] = 10
        assert self.cache.get(10) == 10

        for i in range(CACHE_SIZE):
            assert self.cache.get(i) == i

        self.cache[DATA_SIZE - 1] = DATA_SIZE - 1
        assert self.cache.get(DATA_SIZE - 1) == DATA_SIZE - 1

        self.cache[DATA_SIZE - CACHE_SIZE] = DATA_SIZE - CACHE_SIZE
        assert self.cache.get(DATA_SIZE - CACHE_SIZE) == DATA_SIZE - CACHE_SIZE

        for i in range(CACHE_SIZE):
            assert self.cache.get(i) == i

        self.cache[1] = 1
        assert self.cache.get(1) == 1

        self.cache[3] = 3
        assert self.cache.get(3) == 3

    def test_put_get_orderly(self):
        for i in range(DATA_SIZE):
            self.cache[i] = i

        for i in range(DATA_SIZE):
            assert self.cache.get(i) == i

        for i in range(DATA_SIZE):
            self.cache[i] = DATA_SIZE - i
        for i in range(DATA_SIZE):
            assert self.cache.get(i) == DATA_SIZE - i

        for i in range(DATA_SIZE - 1, -1, -1):
            self.cache[i] = i
        for i in range(DATA_SIZE):
            self.cache[i] = i

        for i in range(DATA_SIZE - 1, -1, -1):
            self.cache[i] = i
            self.cache[i] = i
            self.cache[i] = i
        for i in range(DATA_SIZE):
            self.cache[i] = i


if __name__ == '__main__':
    unittest.main()
