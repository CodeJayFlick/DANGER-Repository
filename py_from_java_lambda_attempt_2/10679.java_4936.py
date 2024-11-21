Here is the translation of the given Java code into Python:

```Python
import unittest


class ShortObjectHashtableTest(unittest.TestCase):

    def test_short_object_hashtable(self):
        ht = {}
        print("Test put method")

        for i in range(1, 5):
            ht[(i * 100)] = "bill" + str(i)

        self.assertEqual(ht.get((100)), "bill")
        self.assertEqual(ht.get((200)), "john")
        self.assertEqual(ht.get((300)), "fred")
        self.assertEqual(ht.get((400)), "tom")

        print("Test contains method")

        for i in range(1, 5):
            self.assertTrue(i * 100 in ht)

        print("Test size method")
        if len(ht) != 4:
            self.fail(f"size should be 4, but it is {len(ht)}")

        print("Test remove")
        del ht[(200)]
        if len(ht) != 3:
            self.fail(f"size should be 3, but it is {len(ht)}")

        for i in range(1, 5):
            self.assertTrue(i * 100 in ht)

        print("Test removeAll")
        ht.clear()
        if len(ht) != 0:
            self.fail(f"size should be 0, but it is {len(ht)}")

        print("Test grow by adding 500 values")
        for i in range(1, 51):
            ht[(i * 10)] = "LAB" + str(i)

        for i in range(1, 501):
            if (i % 10) != 0:
                self.fail(f"hashtable contains key {i}, but it shouldn't")
            elif i not in list(ht.keys()):
                self.fail(f"hashtable should contain key {i}, but it doesn't")


if __name__ == '__main__':
    unittest.main()
```

Note: Python does not have a direct equivalent to Java's `ShortObjectHashtable` class. The above code uses a dictionary (`{}`) instead, which is similar in functionality.