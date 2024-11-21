Here is the translation of the given Java code into Python:

```Python
import unittest


class ObjectKeyIndexerTest(unittest.TestCase):

    def test_object_key_indexer(self):
        indexer = ObjectKeyIndexer(13)

        print("Test put method")
        for i in range(ord('A'), ord('G')+1):
            key = chr(i)
            index = indexer.put(key)
            self.assertEqual(index, i-ord('A'))

        indexer.remove('D')
        self.assertEqual(indexer.get('D'), -1)

        print("Test grow")

        for i in range(20):
            key = 'LAB' + str(i)
            indexer.put(key)

        for i in range(ord('A'), ord('G')+1):
            key = chr(i)
            self.assertEqual(indexer.get(key), i-ord('A'))

        self.assertEqual(indexer.get('M'), -1)

        print("Test capacity")
        self.assertEqual(indexer.capacity, 37)

        indexer.clear()
        for i in range(100):
            key = 'LAB' + str(i)
            indexer.put(key)

        for i in range(100):
            self.assertEqual(indexer.get('LAB'+str(i)), i)


if __name__ == '__main__':
    unittest.main()
```

Please note that Python does not have a direct equivalent to Java's `@Test` annotation. Instead, we use the `unittest.TestCase` class and define test methods using the standard method naming convention (`test_`).