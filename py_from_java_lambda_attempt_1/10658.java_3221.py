Here is the translation of the Java code into Python:

```Python
class IntArrayArrayTest:
    def __init__(self):
        pass

    def test_simple_get_put(self):
        baa = [[], []]
        self.assertIsNone(baa[0])
        self.assertIsNone(baa[100])
        baa[0] = [0, 1, 2]
        b = baa[0]
        self.assertEqual(3, len(b))
        self.assertEqual(0, b[0])
        self.assertEqual(1, b[1])
        self.assertEqual(2, b[2])

        baa[1] = []
        b = baa[1]
        self.assertEqual(0, len(b))

        baa[2] = [5]
        b = baa[2]
        self.assertEqual(1, len(b))

        del baa[1]
        self.assertIsNone(baa[1])

    def test_many(self):
        baa = [[], []]

        for i in range(1000):
            t = i
            baa.append([t, (t + 1), (t + 2), (t + 3), (t + 4)])

        for i in range(1000):
            b = baa[i]
            self.assertEqual(5, len(b))
            for j in range(5):
                t = i + j
                self.assertEqual(t, b[j])

        while len(baa) > 1:
            del baa[0]

        self.assertEqual(4, len(baa))

    def test(self):
        self.test_simple_get_put()
        self.test_many()

if __name__ == "__main__":
    unittest.main()
```

Note: This Python code is not a direct translation of the Java code. It's more like an equivalent implementation in Python. The original Java code uses JUnit for testing, which doesn't have a direct equivalent in Python (although there are some libraries that provide similar functionality).