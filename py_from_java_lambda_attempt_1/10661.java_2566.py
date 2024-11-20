Here is the translation of the given Java code into Python:

```Python
import unittest

class IntListIndexerTest(unittest.TestCase):

    def test_int_list_indexer(self):
        indexer = IntListIndexer(5, 13)

        print("Test adding to some lists")
        for _ in range(6):
            indexer.add(list(range(_)))
        self.assertEqual(indexer.get_list_size(0), [4,3])
        self.assertEqual(indexer.get_list_size(1), list(range(6))[::-1])

        print("Test delete")
        indexer.remove(1, 2)
        indexer.remove(1, 1)
        indexer.add(4)
        for _ in range(3):
            indexer.add(_)
        self.assertEqual(indexer.get_list_size(0), [4,3])
        self.assertEqual(indexer.get_list_size(1), list(range(6))[::-1])

        print("Test remove all")
        indexer.remove_all(0)
        self.assertEqual(indexer.get_list_size(0), [])

        print("Test capacity and num lists")
        if indexer.get_capacity() != 13:
            self.fail(f"The capacity should be 13, but it is {indexer.get_capacity()}")
        if indexer.get_num_lists() != 5:
            self.fail(f"The number of lists should be 5, but it is {indexer.get_num_lists()}")

        print("Test size")
        if indexer.get_size() != 6:
            self.fail(f"The size should be 6, but it is {indexer.get_size()}")

        print("Test resize")
        indexer.grow_capacity(17)
        indexer.grow_num_lists(9)

        print("Test capacity and num lists after resize")
        if indexer.get_capacity() != 17:
            self.fail(f"The capacity should be 17, but it is {indexer.get_capacity()}")
        if indexer.get_num_lists() != 9:
            self.fail(f"The number of lists should be 9, but it is {indexer.get_num_lists()}")

        print("Test clear")
        indexer.clear()
        for _ in range(5):
            self.assertEqual(indexer.get_list_size(_), [])

    def test_append(self):
        indexer = IntListIndexer(1, 13)
        for i in range(3):
            indexer.append(i)

        self.assertEqual(indexer.get_list_size(0), [0,1,2])

    def test_add_to_all_lists(self):
        indexer = IntListIndexer(9, 17)
        indexer.clear()

        for _ in range(6):
            for i in range(_+1):
                indexer.append(i)

        self.assertEqual(indexer.get_list_size(0), list(range(6)))
        self.assertEqual(indexer.get_list_size(1), list(range(7))[::-1])
        self.assertEqual(indexer.get_list_size(2), list(range(8))[::-1])
        self.assertEqual(indexer.get_list_size(3), list(range(9))[::-1])
        self.assertEqual(indexer.get_list_size(4), list(range(10))[::-1])
        self.assertEqual(indexer.get_list_size(5), list(range(11))[::-1])
        self.assertEqual(indexer.get_list_size(6), list(range(12))[::-1])
        self.assertEqual(indexer.get_list_size(7), list(range(13))[::-1])
        self.assertEqual(indexer.get_list_size(8), list(range(14))[::-1])

if __name__ == '__main__':
    unittest.main()
```

Note: The `IntListIndexer` class is not provided in the given Java code, so I assumed its functionality based on the test cases.