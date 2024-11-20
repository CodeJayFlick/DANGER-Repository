Here is the translation of the Java code into Python:

```Python
import unittest

class ObjectRangeMapTest(unittest.TestCase):

    def testGetSet(self):
        map = ObjectRangeMap()
        obj1 = object()
        map.set_object(10, 20, obj1)
        self.assertIsNone(map.get_object(0))
        self.assertIsNone(map.get_object(9))
        self.assertEqual(obj1, map.get_object(10))
        self.assertEqual(obj1, map.get_object(20))
        self.assertIsNone(map.get_object(21))

    def testGetSet2(self):
        map = ObjectRangeMap()
        obj1 = object()
        obj2 = object()
        map.set_object(10, 60, obj1)
        map.set_object(5, 15, obj2)
        self.assertIsNone(map.get_object(4))
        self.assertEqual(obj2, map.get_object(5))
        self.assertEqual(obj2, map.get_object(10))
        self.assertEqual(obj2, map.get_object(15))
        self.assertEqual(obj1, map.get_object(16))
        self.assertEqual(obj1, map.get_object(60))
        self.assertIsNone(map.get_object(61))

    def testGetSet3(self):
        map = ObjectRangeMap()
        obj1 = object()
        obj2 = object()
        map.set_object(10, 60, obj1)
        map.set_object(55, 65, obj2)
        self.assertIsNone(map.get_object(9))
        self.assertEqual(obj1, map.get_object(10))
        self.assertEqual(obj1, map.get_object(54))
        self.assertEqual(obj2, map.get_object(55))
        self.assertEqual(obj2, map.get_object(60))
        self.assertEqual(obj2, map.get_object(65))
        self.assertIsNone(map.get_object(66))

    def testGetSet4(self):
        map = ObjectRangeMap()
        obj1 = object()
        obj2 = object()
        map.set_object(10, 60, obj1)
        map.set_object(10, 65, obj2)
        self.assertIsNone(map.get_object(9))
        self.assertEqual(obj2, map.get_object(10))
        self.assertEqual(obj2, map.get_object(54))
        self.assertEqual(obj2, map.get_object(55))
        self.assertEqual(obj2, map.get_object(60))
        self.assertEqual(obj2, map.get_object(65))
        self.assertIsNone(map.get_object(66))

    def testGetSet5(self):
        map = ObjectRangeMap()
        obj1 = object()
        obj2 = object()
        map.set_object(10, 60, obj1)
        map.set_object(5, 60, obj2)
        self.assertIsNone(map.get_object(4))
        self.assertEqual(obj2, map.get_object(5))
        self.assertEqual(obj2, map.get_object(9))
        self.assertEqual(obj2, map.get_object(10))
        self.assertEqual(obj2, map.get_object(60))
        self.assertIsNone(map.get_object(61))

    def testClear(self):
        map = ObjectRangeMap()
        obj1 = object()
        map.set_object(20, 50, obj1)
        map.clear_range(10, 29)
        self.assertIsNone(map.get_object(19))
        self.assertEqual(obj1, map.get_object(30))
        self.assertEqual(obj1, map.get_object(50))
        self.assertIsNone(map.get_object(51))

    def testClear2(self):
        map = ObjectRangeMap()
        obj1 = object()
        map.set_object(20, 50, obj1)
        map.clear_range(41, 60)
        self.assertIsNone(map.get_object(19))
        self.assertEqual(obj1, map.get_object(20))
        self.assertEqual(obj1, map.get_object(40))
        self.assertIsNone(map.get_object(41))
        self.assertIsNone(map.get_object(50))

    def testClear3(self):
        map = ObjectRangeMap()
        obj1 = object()
        map.set_object(20, 50, obj1)
        map.clear_range(30, 40)
        self.assertIsNone(map.get_object(19))
        self.assertEqual(obj1, map.get_object(20))
        self.assertEqual(obj1, map.get_object(29))
        self.assertIsNone(map.get_object(30))
        self.assertIsNone(map.get_object(40))
        self.assertEqual(obj1, map.get_object(41))
        self.assertEqual(obj1, map.get_object(50))

    def testClear4(self):
        map = ObjectRangeMap()
        obj1 = object()
        map.set_object(20, 50, obj1)
        map.clear_range(10, 60)
        self.assertIsNone(map.get_object(19))
        self.assertIsNone(map.get_object(20))
        self.assertIsNone(map.get_object(29))
        self.assertIsNone(map.get_object(30))
        self.assertIsNone(map.get_object(40))
        self.assertIsNone(map.get_object(41))
        self.assertIsNone(map.get_object(50))

    def testClear5(self):
        map = ObjectRangeMap()
        obj1 = object()
        map.set_object(20, 50, obj1)
        map.clear_range(10, 15)
        self.assertIsNone(map.get_object(19))
        self.assertEqual(obj1, map.get_object(20))
        self.assertEqual(obj1, map.get_object(50))

    def testContains(self):
        map = ObjectRangeMap()
        obj1 = object()
        map.set_object(20, 30, obj1)
        map.set_object(40, 50, obj1)
        map.set_object(60, 70, obj1)
        map.set_object(80, 90, obj1)

        self.assertFalse(map.contains(10))
        self.assertFalse(map.contains(19))
        self.assertTrue(map.contains(20))
        self.assertTrue(map.contains(25))
        self.assertTrue(map.contains(30))

    def testIterator(self):
        map = ObjectRangeMap()
        obj1 = object()
        map.set_object(20, 30, obj1)
        map.set_object(40, 50, obj1)
        map.set_object(60, 70, obj1)
        map.set_object(80, 90, obj1)

        it = map.get_index_range_iterator()
        self.assertTrue(it.has_next())

        range = it.next()
        self.assertEqual(range.start, 20)
        self.assertEqual(range.end, 30)

        range = it.next()
        self.assertEqual(range.start, 40)
        self.assertEqual(range.end, 50)

        range = it.next()
        self.assertEqual(range.start, 60)
        self.assertEqual(range.end, 70)

        range = it.next()
        self.assertEqual(range.start, 80)
        self.assertEqual(range.end, 90)

        self.assertFalse(it.has_next())

    def testIterator2(self):
        map = ObjectRangeMap()
        obj1 = object()
        map.set_object(20, 30, obj1)
        map.set_object(40, 50, obj1)
        map.set_object(60, 70, obj1)
        map.set_object(80, 90, obj1)

        it = map.get_index_range_iterator(25, 85)
        self.assertTrue(it.has_next())

        range = it.next()
        self.assertEqual(range.start, 25)
        self.assertEqual(range.end, 30)

        range = it.next()
        self.assertEqual(range.start, 40)
        self.assertEqual(range.end, 50)

        range = it.next()
        self.assertEqual(range.start, 60)
        self.assertEqual(range.end, 70)

        range = it.next()
        self.assertEqual(range.start, 80)
        self.assertEqual(range.end, 85)

        self.assertFalse(it.has_next())

    def testIterator3(self):
        map = ObjectRangeMap()
        obj1 = object()
        map.set_object(20, 30, obj1)
        map.set_object(40, 50, obj1)
        map.set_object(60, 70, obj1)
        map.set_object(80, 90, obj1)

        it = map.get_index_range_iterator(0, 25)
        self.assertFalse(it.has_next())

    def testIterator4(self):
        map = ObjectRangeMap()
        obj1 = object()
        map.set_object(20, 30, obj1)
        map.set_object(40, 50, obj1)
        map.set_object(60, 70, obj1)
        map.set_object(80, 90, obj1)

        it = map.get_index_range_iterator(65, 100)
        self.assertTrue(it.has_next())

        range = it.next()
        self.assertEqual(range.start, 65)
        self.assertEqual(range.end, 70)

        range = it.next()
        self.assertEqual(range.start, 80)
        self.assertEqual(range.end, 90)

        self.assertFalse(it.has_next())

    def testIterator5(self):
        map = ObjectRangeMap()
        obj1 = object()
        map.set_object(20, 30, obj1)
        map.set_object(40, 50, obj1)
        map.set_object(60, 70, obj1)
        map.set_object(80, 90, obj1)

        it = map.get_index_range_iterator(42, 48)
        self.assertTrue(it.has_next())

        range = it.next()
        self.assertEqual(range.start, 42)
        self.assertEqual(range.end, 48)

        self.assertFalse(it.has_next())

    def testIterator6(self):
        map = ObjectRangeMap()
        obj1 = object()
        map.set_object(20, 30, obj1)
        map.set_object(40, 50, obj1)
        map.set_object(60, 70, obj1)
        map.set_object(80, 90, obj1)

        it = map.get_index_range_iterator(35, 55)
        self.assertTrue(it.has_next())

        range = it.next()
        self.assertEqual(range.start, 40)
        self.assertEqual(range.end, 50)

        self.assertFalse(it.has_next())


if __name__ == '__main__':
    unittest.main()

```

Please note that Python does not have a direct equivalent to Java's `ObjectRangeMap` class. This code is just an approximation of the provided test cases in Python using built-in data structures and functions.