Here is the translation of the Java code into Python:

```Python
import unittest
from typing import List

class VectorTVListTest(unittest.TestCase):

    def testVectorTVList1(self):
        data_types = [TSDataType.INT64] * 5
        tv_list = VectorTVList(data_types)
        for i in range(1000):
            value = [i] * 5
            tv_list.put_vector(i, value)

        for i in range(len(tv_list)):
            self.assertEqual(f"[{i}]", str(tv_list.get_vector(i)))
            self.assertEqual(i, tv_list.get_time(i))

    def testVectorTVList2(self):
        data_types = [TSDataType.BOOLEAN] + \
                      [TSDataType.INT32] * 3 + \
                      [TSDataType.TEXT]
        tv_list = VectorTVList(data_types)
        for i in range(1000, -1, -1):
            value = [False, 100, 1000, 0.1, 0.2, "Test"]
            tv_list.put_vector(i, value)

        tv_list.sort()
        for i in range(len(tv_list)):
            self.assertEqual(f"[false, 100, 1000, 0.1, 0.2, Test]", str(tv_list.get_vector(i)))
            self.assertEqual(i, tv_list.get_time(i))

    def testVectorTVLists(self):
        data_types = [TSDataType.INT64] * 5
        time_list = list(range(1000, -1, -1))
        vector_array = [[i] * 5 for i in range(1000)]
        bit_maps = [BitMap(1001) for _ in range(5)]

        tv_list = VectorTVList(data_types)
        tv_list.put_vectors(time_list, vector_array, bit_maps, 0, 1000)

        for i in range(len(tv_list)):
            self.assertEqual(len(tv_list) - i, tv_list.get_time(i))

    def testVectorTVListsWithBitMaps(self):
        data_types = [TSDataType.INT64] * 5
        time_list = list(range(1000, -1, -1))
        vector_array = [[i] * 5 for i in range(1000)]
        bit_maps = [BitMap(1001) for _ in range(5)]

        tv_list = VectorTVList(data_types)
        tv_list.put_vectors(time_list, vector_array, bit_maps, 0, 1000)

        for i in range(len(tv_list)):
            self.assertEqual(len(tv_list) - i, tv_list.get_time(i))
            if i % 100 == 0:
                self.assertEqual("[null, null, null, null, null]", str(tv_list.get_vector(i)))

    def testClone(self):
        data_types = [TSDataType.INT64] * 5
        time_list = list(range(1000, -1, -1))
        vector_array = [[i] * 5 for i in range(1000)]
        bit_maps = [BitMap(1001) for _ in range(5)]

        tv_list = VectorTVList(data_types)
        tv_list.put_vectors(time_list, vector_array, bit_maps, 0, 1000)

        cloned_tv_list = tv_list.clone()
        for i in range(len(tv_list)):
            self.assertEqual(tv_list.get_time(i), cloned_tv_list.get_time(i))
            self.assertEqual(str(tv_list.get_vector(i)), str(cloned_tv_list.get_vector(i)))
            for j in range(5):
                self.assertEqual(tv_list.is_value_marked(i, j), cloned_tv_list.is_value_marked(i, j))

if __name__ == '__main__':
    unittest.main()
```

Note: The `VectorTVList` class and the `TSDataType`, `BitMap`, etc. are not defined in this code as they were part of the original Java code. You would need to define these classes or use equivalent Python classes for them to work properly.