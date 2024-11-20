Here is the translation of the given Java code into Python:

```Python
import unittest
from tempfile import TemporaryFile as createTempFile
from io import StringIO, BytesIO

class IntPropertySetTest(unittest.TestCase):

    def setUp(self):
        self.ps = IntPropertySet("Test")

    def testGetSize(self):
        for i in range(1000):
            self.ps.put_int(i * 10000, i)
        self.assertEqual(1000, self.ps.get_size())

    def testGetProperty(self):
        for i in range(1000):
            self.ps.put_int(i * 10000, i)

        self.assertEqual(0, self.ps.get_property(0))
        self.assertEqual(50, self.ps.get_property(500000))
        for i in range(1000):
            self.assertEqual(i, self.ps.get_property(10000 * i))

    def testPropertyIndex(self):
        for i in range(1000):
            self.ps.put_int(i * 10000, i)

        self.assertEqual(0, self.ps.get_first_property_index())
        self.assertEqual(9990000, self.ps.get_last_property_index())
        self.assertEqual(10000, self.ps.get_next_property_index(0))
        self.assertEqual(0, self.ps.get_previous_property_index(10000))

    def testPropertyIndex2(self):
        for i in range(10000):
            self.ps.put_int(i * 3, i)
        self.assertEqual(10000, self.ps.get_size())

        self.assertEqual(0, self.ps.get_first_property_index())
        self.assertEqual(9999 * 3, self.ps.get_last_property_index())
        self.assertEqual(3, self.ps.get_next_property_index(0))
        self.assertEqual(0, self.ps.get_previous_property_index(3))

    def testPropertyIndex3(self):
        for i in range(10000):
            self.ps.put_int(i, i)
        self.assertEqual(10000, self.ps.get_size())

        self.assertEqual(0, self.ps.get_first_property_index())
        self.assertEqual(9999, self.ps.get_last_property_index())
        self.assertEqual(1, self.ps.get_next_property_index(0))
        self.assertEqual(2, self.ps.get_previous_property_index(3))

    def testIterator(self):
        for i in range(1000):
            self.ps.put_int(i * 100, i)
        it = iter((i * 10000) for i in range(1000))
        i = 0
        while True:
            try:
                l = next(it)
                self.assertEqual(l, i * 100)
                i += 1
            except StopIteration:
                break

    def testIterator2(self):
        for i in range(10000):
            self.ps.put_int(i, i)
        it = iter((i) for i in range(10000))
        i = 0
        while True:
            try:
                l = next(it)
                self.assertEqual(l, i)
                i += 1
            except StopIteration:
                break

    def testSerialization(self):
        for i in range(10000):
            self.ps.put_int(i, i)

        tmp_file = createTempFile("IntPropertySetTest", ".ser")
        try:
            with open(tmp_file.name, 'wb') as f:
                import pickle
                pickle.dump(self.ps, f)
            self.ps = None

            with open(tmp_file.name, 'rb') as f:
                self.ps = pickle.load(f)

        finally:
            tmp_file.close()

        for i in range(10000):
            self.assertEqual(i, self.ps.get_property(i))

if __name__ == '__main__':
    unittest.main()
```

Please note that Python does not have direct equivalent of Java's `IntPropertySet` class. The above code is a translation of the given Java code into Python and it may require some modifications to work correctly in your specific use case.