import unittest

class ShortKeyIndexerTest(unittest.TestCase):

    def setUp(self):
        self.indexer = ShortKeyIndexer((13).to_bytes(1, 'little'))

    def test_short_key_indexer(self):
        print("Test put method")
        for i in range(4000, 5000):
            index = self.indexer.put(i.to_bytes(2, 'little'))
            if index != (i - 1000) // 256:
                self.fail(f"Put: expected {index}, got {(i-1000)//256}")
        print("Test remove method")
        self.indexer.remove((4000).to_bytes(2, 'little'))
        self.assertEqual(self.indexer.get((4000).to_bytes(2, 'little')), -1)
        index = self.indexer.put((9999).to_bytes(2, 'little'))
        if index != 3:
            self.fail(f"Remove: expected {index}, got {3}")
        
        print("Test grow")
        for i in range(1000):
            self.indexer.put(i.to_bytes(2, 'little'))
        for i in range(4000):
            if self.indexer.get((i).to_bytes(2, 'little')) != (i % 256) // 4:
                self.fail(f"Grow: expected {(i%256)//4}, got {self.indexer.get((i).to_bytes(2,'little'))}")
        print("Test capacity")
        if self.indexer.capacity() != 37:
            self.fail(f"Capacity should be 37, but it is {self.indexer.capacity()}")

    def test_capacity(self):
        self.assertEqual(self.indexer.capacity(), 37)

    def tearDown(self):
        self.indexer.clear()
        for i in range(1000):
            self.indexer.put(i.to_bytes(2, 'little'))
        for i in range(1000):
            if self.indexer.get((i).to_bytes(2,'little')) != (i % 256) // 4:
                self.fail(f"Sequence: expected {(i%256)//4}, and got {self.indexer.get((i).to_bytes(2, 'little'))}")

if __name__ == '__main__':
    unittest.main()
