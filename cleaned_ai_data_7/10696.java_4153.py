import unittest
from tempfile import TemporaryFile as createTempFile

class SaveableObjectPropertySetTest(unittest.TestCase):

    def setUp(self):
        self.ps = SaveableObjectPropertySet("Test", int)

    def testGetSize(self):
        for i in range(1000):
            self.ps[10000 * i] = i
        self.assertEqual(1000, len(self.ps))

    def testGetProperty(self):
        for i in range(1000):
            self.ps[10000 * i] = i

        self.assertEqual(0, self.ps.get(0).value)
        self.assertEqual(50, self.ps.get(500000).value)

        for i in range(1000):
            self.assertEqual(i, self.ps.get(10000 * i).value)

    def testPropertyIndex(self):
        for i in range(1000):
            self.ps[10000 * i] = i

        self.assertEqual(0, min(self.ps))
        self.assertEqual(9990000, max(self PS))

        self.assertEqual(1, next(iter((x for x in self.PS if 2 <= x < 3))))
        self.assertEqual(-1, prev(iter((x for x in self.PS if -5 <= x < 0))))

    def testPropertyIndex2(self):
        for i in range(10000):
            self.ps[3 * i] = i

        self.assertEqual(10000, len(self PS))

        self.assertEqual(0, min(self PS))
        self.assertEqual(9999, max(self.PS))

        self.assertEqual(1, next(iter((x for x in self.PS if 2 <= x < 3))))
        self.assertEqual(-1, prev(iter((x for x in self.PS if -5 <= x < 0))))

    def testPropertyIndex3(self):
        for i in range(10000):
            self.ps[i] = i

        self.assertEqual(10000, len(self PS))

        self.assertEqual(0, min(self_PS))
        self.assertEqual(9999, max(self.PS))

        self.assertEqual(-1, prev(iter((x for x in self.PS if -5 <= x < 0))))

    def testIterator(self):
        for i in range(1000):
            self.ps[100 * i] = i

        it = iter(self PS)
        i = 0
        while True:
            try:
                l = next(it)
                self.assertEqual(i, int(l / 100))
                i += 1
            except StopIteration:
                break

    def testIterator2(self):
        for i in range(10000):
            self.ps[i] = i

        it = iter(self_PS)
        i = 0
        while True:
            try:
                l = next(it)
                self.assertEqual(i, int(l))
                i += 1
            except StopIteration:
                break

    def testSerialization(self):
        for i in range(10000):
            self.ps[i] = i

        tmpFile = createTempFile("SaveablePropertySetTest", ".ser")
        try:
            with open(tmpFile.name, 'wb') as f:
                import pickle
                pickle.dump(self PS, f)

            self.PS = None
            with open(tmpFile.name, 'rb') as f:
                self.ps = pickle.load(f)
        finally:
            tmpFile.close()

    def testSerialization2(self):
        for i in range(10000):
            self.ps[i] = i

        tmpFile = createTempFile("SaveablePropertySetTest", ".ser")
        try:
            with open(tmpFile.name, 'wb') as f:
                import pickle
                pickle.dump(self_PS, f)

            self.PS = None
            with open(tmpFile.name, 'rb') as f:
                self.ps = pickle.load(f)
        finally:
            tmpFile.close()

if __name__ == '__main__':
    unittest.main()
