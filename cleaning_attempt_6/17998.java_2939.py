import unittest
from bitarray import bitarray

class LongTVListTest(unittest.TestCase):

    def test_long_tv_list1(self):
        tv_list = []
        for i in range(1000):
            tv_list.append((i, i))
        tv_list.sort(key=lambda x: x[0])
        for i in range(len(tv_list)):
            self.assertEqual(i, tv_list[i][1])
            self.assertEqual(i, tv_list[i][0])

    def test_long_tv_list2(self):
        tv_list = []
        for i in range(1000, -1, -1):
            tv_list.append((i, i))
        tv_list.sort(key=lambda x: x[0])
        for i in range(len(tv_list)):
            self.assertEqual(i, tv_list[i][1])
            self.assertEqual(i, tv_list[i][0])

    def test_long_tv_list3(self):
        import random
        tv_list = []
        inputs = []
        for _ in range(10000):
            time = random.randint(0, 9999)
            value = random.randint(0, 9999)
            tv_list.append((time, value))
            inputs.append((time, value))
        tv_list.sort(key=lambda x: x[0])
        inputs.sort(key=lambda x: x[0])
        for i in range(len(tv_list)):
            self.assertEqual(inputs[i][0], tv_list[i][0])
            self.assertEqual(inputs[i][1], tv_list[i][1])

    def test_put_longsWithout_bit_map(self):
        tv_list = []
        time_list = list(range(1000, -1, -1))
        value_list = [i for i in range(1000, -1, -1)]
        tv_list.extend([(time, value) for time, value in zip(time_list, value_list)])
        tv_list.sort(key=lambda x: x[0])
        for i in range(len(tv_list)):
            self.assertEqual(len(tv_list) - i, tv_list[i][1])
            self.assertEqual(len(tv_list) - i, tv_list[i][0])

    def test_put_intsWith_bit_map(self):
        tv_list = []
        time_list = list(range(1000, -1, -1))
        value_list = [i for i in range(1000, -1, -1)]
        bit_array = bitarray(length=1001)
        null_count = 0
        for i in range(len(time_list)):
            if i % 100 == 0:
                bit_array[i] = True
                continue
            tv_list.append((time_list[i], value_list[i]))
        tv_list.sort(key=lambda x: x[0])
        for i in range(1, len(value_list)):
            if i % 100 == 0:
                null_count += 1
                continue
            self.assertEqual(i, tv_list[i - null_count][1])
            self.assertEqual(i, tv_list[i - null_count][0])

    def test_clone(self):
        tv_list = []
        time_list = list(range(1000, -1, -1))
        value_list = [i for i in range(1000, -1, -1)]
        bit_array = bitarray(length=1001)
        null_count = 0
        for i in range(len(time_list)):
            if i % 100 == 0:
                bit_array[i] = True
                continue
            tv_list.append((time_list[i], value_list[i]))
        tv_list.sort(key=lambda x: x[0])
        cloned_tv_list = [item[:] for item in tv_list]
        for i in range(len(tv_list)):
            self.assertEqual(tv_list[i][1], cloned_tv_list[i][1])
            self.assertEqual(tv_list[i][0], cloned_tv_list[i][0])

if __name__ == '__main__':
    unittest.main()
