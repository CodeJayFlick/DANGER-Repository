Here is the translation of the given Java code into equivalent Python:

```Python
import unittest

class AnnotatedSaveable:
    def __init__(self):
        self.primitive_boolean = None
        self.object_boolean = None
        self.primitive_byte = None
        self.object_byte = None
        self.arr_of_byte = []
        self.primitive_double = None
        self.object_double = None
        self.arr_of_double = []
        self.primitive_float = None
        self.object_float = None
        self.arr_of_float = []
        self.primitive_int = None
        self.object_int = None
        self.arr_of_int = []
        self.primitive_long = None
        self.object_long = None
        self.arr_of_long = []
        self.primitive_short = None
        self.object_short = None
        self.arr_of_short = []
        self.object_string = None
        self.arr_of_string = []

    def get_schema_version(self):
        return 0

class FakeObjectStorage:
    def __init__(self):
        self.objects = []

    def put_int(self, value):
        self.objects.append(value)

    def put_byte(self, value):
        self.objects.append(value)

    def put_short(self, value):
        self.objects.append(value)

    def put_long(self, value):
        self.objects.append(value)

    def put_string(self, value):
        self.objects.append(value)

    def put_boolean(self, value):
        self.objects.append(value)

    def put_float(self, value):
        self.objects.append(value)

    def get_int(self):
        return int(next(iter(self.objects)))

    def get_byte(self):
        return next(iter(self.objects))

    def get_short(self):
        return short(next(iter(self.objects)))

    def get_long(self):
        return long(next(iter(self.objects)))

    def get_string(self):
        return str(next(iter(self.objects)))

    def put_ints(self, value):
        self.objects.append(value)

    def put_bytes(self, value):
        self.objects.append(value)

    def put_shorts(self, value):
        self.objects.append(value)

    def put_longs(self, value):
        self.objects.append(value)

    def put_floats(self, value):
        self.objects.append(value)

    def put_doubles(self, value):
        self.objects.append(value)

    def get_ints(self):
        return list(map(int, self.objects))

    def get_bytes(self):
        return list(map(byte, self.objects))

    def get_shorts(self):
        return list(map(short, self.objects))

    def get_longs(self):
        return list(map(long, self.objects))

    def get_floats(self):
        return list(map(float, self.objects))

    def get_doubles(self):
        return list(map(double, self.objects))

    def get_strings(self):
        return list(map(str, self.objects))


class Test(unittest.TestCase):

    def test_all_field_types(self):
        saveable = AnnotatedSaveable()
        saveable.primitive_boolean = True
        saveable.primitive_byte = 1
        saveable.primitive_double = 2.0
        saveable.primitive_float = 3.0
        saveable.primitive_int = 4
        saveable.primitive_long = 5
        saveable.primitive_short = 6
        saveable.object_boolean = False
        saveable.object_byte = 7
        saveable.object_double = 8.0
        saveable.object_float = 9.0
        saveable.object_int = 10
        saveable.object_long = 11
        saveable.object_short = 12
        saveable.object_string = "13"
        saveable.arr_of_byte = []
        saveable.arr_of_double = [14.0, 15.0]
        saveable.arr_of_float = [16.0]
        saveable.arr_of_int = [17, 18, 19]
        saveable.arr_of_long = [20L, 21L]
        saveable.arr_of_short = [22]
        saveable.arr_of_string = ["23", "24"]

        storage = FakeObjectStorage()
        saveable.save(storage)

        restored = AnnotatedSaveable()
        restored.restore(storage)

        self.assertEqual(restored.primitive_boolean, True)
        self.assertEqual(restored.primitive_byte, 1)
        self.assertAlmostEqual(restored.primitive_double, 2.0)
        self.assertAlmostEqual(restored.primitive_float, 3.0)
        self.assertEqual(restored.primitive_int, 4)
        self.assertEqual(restored.primitive_long, 5L)
        self.assertEqual(restored.primitive_short, 6)

        self.assertFalse(restored.object_boolean)
        self.assertEqual(restored.object_byte, 7)
        self.assertAlmostEqual(restored.object_double, 8.0)
        self.assertAlmostEqual(restored.object_float, 9.0)
        self.assertEqual(restored.object_int, 10)
        self.assertEqual(restored.object_long, 11L)
        self.assertEqual(restored.object_short, 12)
        self.assertEqual(restored.object_string, "13")

        self.assertListEqual(restored.arr_of_byte, [])
        self.assertAlmostEqual(restored.arr_of_double[0], 14.0)
        self.assertAlmostEqual(restored.arr_of_double[1], 15.0)
        self.assertAlmostEqual(restored.arr_of_float[0], 16.0)
        self.assertEqual(restored.arr_of_int, [17, 18, 19])
        self.assertListEqual(restored.arr_of_long, [20L, 21L])
        self.assertListEqual(restored.arr_of_short, [22])
        self.assertListEqual(restored.arr_of_string, ["23", "24"])

    def test_fields_alphabetized(self):
        saveable = AnnotatedSaveable()
        expected = [
            bool,
            byte,
            double,
            float,
            int,
            long,
            short,
            str,
            type(None),
            type(None)
        ]
        self.assertListEqual(saveable.get_object_storage_fields(), expected)


if __name__ == '__main__':
    unittest.main()
```