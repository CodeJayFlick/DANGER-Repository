import unittest


class LongKeyIndexerTest(unittest.TestCase):

    def test_long_key_indexer(self):
        indexer = LongKeyIndexer(13)

        print("Test put method")
        for i in range(7):
            self.assertEqual(indexer.put(i * 1000), i)
        self.assertEqual(indexer.get(123), 4)
        self.assertEqual(indexer.get(456), 5)
        self.assertEqual(indexer.get(1789), 6)

        print("Test remove method")
        indexer.remove(4000)
        self.assertEqual(indexer.get(4000), -1)
        self.assertEqual(indexer.put(9999), 3)

        print("Test grow")
        for i in range(20):
            indexer.put(i)
        self.assertEqual(indexer.get(1000), 0)
        self.assertEqual(indexer.get(2000), 1)
        self.assertEqual(indexer.get(3000), 2)
        self.assertEqual(indexer.get(4000), -1)
        self.assertEqual(indexer.get(123), 4)

        print("Test capacity")
        self.assertEqual(indexer.capacity, 37)

        indexer.clear()
        for i in range(100):
            indexer.put(i)
        for i in range(100):
            self.assertEqual(indexer.get(i), i)


if __name__ == '__main__':
    unittest.main()
