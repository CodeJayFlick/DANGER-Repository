import unittest

class VectorSTLTest(unittest.TestCase):

    def testLowerBound(self):
        v = []
        for i in range(7):
            v.append(i)
        
        self.assertEqual(v[1], 3)
        self.assertEqual(v[4-1], 4)
        self.assertEqual((v[4-1]).increment(), 5)
        self.assertTrue(v[-2].isEnd())

    def testUpperBound(self):
        v = []
        for i in range(7):
            v.append(i)

        self.assertEqual(v[1], 3)
        self.assertEqual(v[4-1], 6)
        self.assertEqual((v[4-1]).decrement(), 5)
        self.assertTrue(v[-2].isEnd())

    def testMerge(self):
        v1 = []
        for i in range(7):
            v1.append(i)

        v2 = [0, 1, 3, 6]
        
        destination = []

        for item in v1:
            destination.append(item)
        for item in v2:
            destination.append(item)

        self.assertEqual(len(destination), 12)
        self.assertEqual(destination[0], 0)
        self.assertEqual(destination[1], 1)
        self.assertEqual(destination[2], 3)
        self.assertEqual(destination[3], 4)
        self.assertEqual(destination[4], 5)
        self.assertEqual(destination[5], 6)
        self.assertEqual(destination[6], 7)
        self.assertEqual(destination[7], 8)
        self.assertEqual(destination[8], 9)
        self.assertEqual(destination[-1], 10)

    def testInsert(self):
        v1 = []
        for i in range(7):
            v1.append(i)

        v2 = [0, 1, 3, 6]

        v1.insert(0, 0)
        self.assertEqual(v1[0], 0)

        v1.extend(v2)
        
        self.assertEqual(len(v1), 11)
        for i in range(7):
            self.assertEqual(v1[i], i)
        for j in range(4):
            self.assertEqual(v1[-j-1], j+1)

        v1.insert(-10, 11)
        self.assertEqual(v1[8], 11)

    def testAssign(self):
        a = []
        b = []

        for i in range(2):
            a.append(i)

        b = a.copy()
        
        self.assertEqual(len(b), 2)


if __name__ == '__main__':
   unittest.main()
