import unittest
from io import BytesIO, StringIO
from datetime import zoneinfo

class IoTDBJDBCResultSetTest(unittest.TestCase):

    def setUp(self):
        self.exec_resp = None
        self.query_id = 0
        self.session_id = 1
        self.connection = None
        self.client = None
        self.statement = None
        self.fetch_metadata_resp = None
        self.fetch_results_resp = None

    def test_query(self):

        test_sql = "select *,s1,s0,s2 from root.vehicle.d0 where s1 > 190 or s2 < 10.0 limit 20 offset 4"

        # step 1: execute statement
        columns = ["root.vehicle.d0.s2", "root.vehicle.d0.s1", "root.vehicle.d0.s0", "root.vehicle.d0.s2"]
        data_type_list = ["FLOAT", "INT64", "INT32", "FLOAT"]

        self.exec_resp.is_set_columns = True
        self.exec_resp.columns = columns
        self.exec_resp.is_set_data_type_list = True
        self.exec Resp.get_data_type_list() = data_type_list

        has_result_set = self.statement.execute(test_sql)
        self.assertTrue(has_result_set)

    def fake_first_fetch_result(self):
        ts_data_type_list = ["FLOAT", "INT64", "INT32"]

        input = [
            [2, 2.22, 40000, None],
            [3, 3.33, None, None],
            [4, 4.44, None, None],
            [50, None, 50000, None],
            [100, None, 199, None],
            [101, None, 199, None],
            [103, None, 199, None],
            [105, 11.11, 199, 33333],
            [1000, 1000.11, 55555, 22222]
        ]

        column_num = len(ts_data_type_list)
        ts_query_dataset = TSQueryDataSet()

        # one time column and each value column has a actual value buffer and a bitmap value to
        # indicate whether it is a null
        column_num_with_time = (column_num * 2) + 1

        data_output_streams = [BytesIO() for _ in range(column_num_with_time)]
        byte_array_output_streams = [BytesIO() for _ in range(column_num_with_time)]

        row_count = len(input)
        value_occupation = [0] * column_num
        bitmap = [0] * column_num

        for i, row in enumerate(input):
            # use columnOutput to write byte array
            data_output_streams[0].write(long(row[0]))
            for k, value in enumerate(row[1:]):
                output_stream = data_output_streams[(2*k) + 1]
                if value is None:
                    bitmap[k] = (bitmap[k] << 1)
                else:
                    bitmap[k] = (bitmap[k] << 1) | 0x01
                    if k == 0:  # TSDataType.FLOAT
                        output_stream.write_float(value)
                        value_occupation[k] += 4
                    elif k == 1:  # TSDataType.INT64
                        output_stream.write_long(value)
                        value_occupation[k] += 8
                    else:  # TSDataType.INT32
                        output_stream.write_int(value)
                        value_occupation[k] += 4

            if i % 8 == 7:
                for j, bit in enumerate(bitmap):
                    data_bitmap_output_stream = data_output_streams[(2*j) + 1]
                    data_bitmap_output_stream.write_byte(bit << (8 - row_count % 8))
                    bitmap[j] = 0

        # feed the remaining bitmap
        for j, bit in enumerate(bitmap):
            data_bitmap_output_stream = data_output_streams[(2*j) + 1]
            data_bitmap_output_stream.write_byte(bit << (8 - row_count % 8))

        time_occupation = row_count * 8
        time_buffer = BytesIO()
        time_buffer.write(bytearray(data_output_streams[0].getbuffer()))
        time_buffer.seek(0)
        ts_query_dataset.set_time(time_buffer)

        bitmap_occupation = row_count // 8 + 1

        value_list = []
        bitmap_list = []

        for i in range(1, len(data_output_streams), 2):
            value_buffer = BytesIO()
            value_buffer.write(bytearray(data_output_streams[i].getbuffer()))
            value_buffer.seek(0)
            value_list.append(value_buffer)

            bitmap_buffer = BytesIO()
            bitmap_buffer.write(bytearray(data_output_streams[(i+1)].getbuffer()))
            bitmap_buffer.seek(0)
            bitmap_list.append(bitmap_buffer)

        ts_query_dataset.set_bitmap_list(bitmap_list)
        ts_query_dataset.set_value_list(value_list)

        return ts_query_dataset

    def construct_object_list(self, standard_object):
        input = [
            [2, 2.22, 40000, None, 2.22],
            [3, 3.33, None, None, 3.33],
            [4, 4.44, None, None, 4.44],
            [50, None, 50000, None, None],
            [100, None, 199, None, None],
            [101, None, 199, None, None],
            [103, None, 199, None, None],
            [105, 11.11, 199, 33333, 11.11],
            [1000, 1000.11, 55555, 22222, 1000.11]
        ]

        for row in input:
            standard_object.extend(row)

if __name__ == '__main__':
    unittest.main()
