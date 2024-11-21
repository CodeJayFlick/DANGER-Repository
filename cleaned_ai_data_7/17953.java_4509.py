import unittest
from io import StringIO
import random
import string

class ElasticSerializableTVListTest(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_es_int_tv_list(self):
        self.test_estvlist(TSDataType.INT32)

    def test_es_long_tv_list(self):
        self.test_estvlist(TSDataType.INT64)

    def test_es_float_tv_list(self):
        self.test_estvlist(TSDataType.FLOAT)

    def test_es_double_tv_list(self):
        self.test_estvlist(TSDataType.DOUBLE)

    def test_es_text_tv_list(self):
        self.test_estvlist(TSDataType.TEXT)

    def test_es_boolean_tv_list(self):
        self.test_estvlist(TSDataType.BOOLEAN)

    def test_estvlist(self, data_type):
        init_estvlist(data_type)
        self.test_put(data_type)
        self.test_ordered_access_by_index(data_type)

    def init_estvlist(self, data_type):
        try:
            tv_list = ElasticSerializableTVList.new_elastic_serializable_tv_list(
                data_type,
                QUERY_ID,
                MEMORY_USAGE_LIMIT_IN_MB,
                CACHE_SIZE
            )
            self.assertEqual(0, len(tv_list))
        except Exception as e:
            self.fail(str(e))

    def test_put(self, data_type):
        try:
            switch (data_type):
                case TSDataType.INT32:
                    for i in range(ITERATION_TIMES):
                        tv_list.put_int(i, i)
                    break
                case TSDataType.INT64:
                    for i in range(ITERATION_TIMES):
                        tv_list.put_long(i, i)
                    break
                case TSDataType.FLOAT:
                    for i in range(ITERATION_TIMES):
                        tv_list.put_float(i, i)
                    break
                case TSDataType.DOUBLE:
                    for i in range(ITERATION_TIMES):
                        tv_list.put_double(i, i)
                    break
                case TSDataType.BOOLEAN:
                    for i in range(ITERATION_TIMES):
                        tv_list.put_boolean(i, i % 2 == 0)
                    break
                case TSDataType.TEXT:
                    for i in range(ITERATION_TIMES):
                        tv_list.put_binary(i, Binary.valueOf(str(i)))
                    break

            self.assertEqual(ITERATION_TIMES, len(tv_list))
        except Exception as e:
            self.fail(str(e))

    def test_ordered_access_by_index(self, data_type):
        try:
            switch (data_type):
                case TSDataType.INT32:
                    for i in range(ITERATION_TIMES):
                        self.assertEqual(i, tv_list.get_time(i))
                        self.assertEqual(i, tv_list.get_int(i))
                    break
                case TSDataType.INT64:
                    for i in range(ITERATION_TIMES):
                        self.assertEqual(i, tv_list.get_time(i))
                        self.assertEqual(i, tv_list.get_long(i))
                    break
                case TSDataType.FLOAT:
                    for i in range(ITERATION_TIMES):
                        self.assertEqual(i, tv_list.get_time(i))
                        self.assertAlmostEqual(i, tv_list.get_float(i), 0)
                    break
                case TSDataType.DOUBLE:
                    for i in range(ITERATION_TIMES):
                        self.assertEqual(i, tv_list.get_time(i))
                        self.assertAlmostEqual(i, tv_list.get_double(i), 0)
                    break
                case TSDataType.BOOLEAN:
                    for i in range(ITERATION_TIMES):
                        self.assertEqual(i, tv_list.get_time(i))
                        self.assertEqual(i % 2 == 0, tv_list.get_boolean(i))
                    break
                case TSDataType.TEXT:
                    for i in range(ITERATION_TIMES):
                        self.assertEqual(i, tv_list.get_time(i))
                        self.assertEqual(Binary.valueOf(str(i)), tv_list.get_binary(i))

            except Exception as e:
                self.fail(str(e))

    def test_memory_control(self):
        init_estvlist(TSDataType.TEXT)

        byte_length_min = SerializableList.INITIAL_BYTE_ARRAY_LENGTH_FOR_MEMORY_CONTROL * 2
        byte_length_max = SerializableList.INITIAL_BYTE_ARRAY_LENGTH_FOR_MEMORY_CONTROL * 8

        random_number_generator = random.Random()

        try:
            for i in range(ITERATION_TIMES):
                tv_list.put_binary(
                    i,
                    Binary.valueOf(generate_random_string(byte_length_min + random_number_generator.randint(0, byte_length_max - byte_length_min)))
                )
            reader = tv_list.construct_point_reader_using_trivial_eviction_strategy()
            while reader.next():
                length = reader.current_binary().get_length()
                self.assertGreaterEqual(length, byte_length_min)
                self.assertLessThan(length, byte_length_max)

        except Exception as e:
            print(str(e))
            self.fail(str(e))

    def generate_random_string(self, length):
        random_string_builder = StringBuilder()

        for i in range(0, length):
            random_string_builder.append('.')

        return str(random_string_builder)


if __name__ == '__main__':
    unittest.main()
