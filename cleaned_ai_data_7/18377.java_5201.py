import math
from unittest import TestCase

class SDTEncoderTest(TestCase):

    def test_int_single_value(self):
        encoder = SDTEncoder()
        encoder.set_comp_deviation(0.01)

        degree = 0
        count = 0
        for time in range(100):
            value = int(10 * math.sin(degree * 3.141592653589793 / 180))
            if encoder.encode_int(time, value):
                count += 1

        self.assertEqual(count, 22)

    def test_double_single_value(self):
        encoder = SDTEncoder()
        encoder.set_comp_deviation(0.01)

        degree = 0
        count = 0
        for time in range(100):
            value = 10 * math.sin(degree * 3.141592653589793 / 180)
            if encoder.encode_double(time, value):
                count += 1

        self.assertEqual(count, 14)

    def test_long_single_value(self):
        encoder = SDTEncoder()
        encoder.set_comp_deviation(0.01)

        degree = 0
        count = 0
        for time in range(100):
            value = int(10 * math.sin(degree * 3.141592653589793 / 180))
            if encoder.encode_long(time, value):
                count += 1

        self.assertEqual(count, 22)

    def test_float_single_value(self):
        encoder = SDTEncoder()
        encoder.set_comp_deviation(0.01)

        degree = 0
        count = 0
        for time in range(100):
            value = float(10 * math.sin(degree * 3.141592653589793 / 180))
            if encoder.encode_float(time, value):
                count += 1

        self.assertEqual(count, 14)

    def test_int_value_array(self):
        encoder = SDTEncoder()
        encoder.set_comp_deviation(0.01)

        degree = 0
        timestamps = [i for i in range(100)]
        values = [(int)(10 * math.sin(degree * 3.141592653589793 / 180)) for _ in range(100)]

        size = encoder.encode(timestamps, values, len(timestamps))

        self.assertEqual(size, 22)

    def test_double_value_array(self):
        encoder = SDTEncoder()
        encoder.set_comp_deviation(0.01)

        degree = 0
        timestamps = [i for i in range(100)]
        values = [(10 * math.sin(degree * 3.141592653589793 / 180)) for _ in range(100)]

        size = encoder.encode(timestamps, values, len(timestamps))

        self.assertEqual(size, 14)

    def test_long_value_array(self):
        encoder = SDTEncoder()
        encoder.set_comp_deviation(0.01)

        degree = 0
        timestamps = [i for i in range(100)]
        values = [(int)(10 * math.sin(degree * 3.141592653589793 / 180)) for _ in range(100)]

        size = encoder.encode(timestamps, values, len(timestamps))

        self.assertEqual(size, 22)

    def test_float_value_array(self):
        encoder = SDTEncoder()
        encoder.set_comp_deviation(0.01)

        degree = 0
        timestamps = [i for i in range(100)]
        values = [(float)(10 * math.sin(degree * 3.141592653589793 / 180)) for _ in range(100)]

        size = encoder.encode(timestamps, values, len(timestamps))

        self.assertEqual(size, 14)
