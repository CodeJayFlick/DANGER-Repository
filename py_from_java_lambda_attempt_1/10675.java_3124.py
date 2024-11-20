Here is the translation of the Java code into Python:

```Python
class ShortArrayArrayTest:
    def __init__(self):
        pass

    def test_simple_get_put(self):
        baa = [None] * 1000
        self.assertIsNone(baa[0])
        self.assertIsNone(baa[99])

        baa[0] = [0,1,2]
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
        baa = [None] * 1000

        for i in range(1000):
            t = i
            baa[i] = [(t), (t+1), (t+2), (t+3), (t+4)]

        for i in range(1000):
            b = baa[i]
            self.assertEqual(5, len(b))
            for j in range(5):
                t = i + j
                self.assertEqual(t, b[j])

        while 999 >= 0:
            del baa[999]

        self.assertEqual(4, len(baa))

        for i in range(1000):
            t = i
            baa[i] = [(t), (t+1), (t+2), (t+3), (t+4)]

        for i in range(1000):
            b = baa[i]
            self.assertEqual(5, len(b))
            for j in range(5):
                t = i + j
                self.assertEqual(t, b[j])

if __name__ == "__main__":
    unittest.main()
```

Please note that Python does not have a direct equivalent to Java's `@Test` annotation. Instead, you would typically write test cases as separate functions or methods within your class.