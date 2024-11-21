import pyodbc
import unittest

class IoTDBInIT(unittest.TestCase):
    sqls = [
        "set storage group to root.ln",
        "create timeseries root.sgd1.s1.qrcode with datatype=TEXT,encoding=PLAIN",
        "insert into root.sgd1.s1(timestamp,qrcode) values(1509465600000,'qrcode001')",
        # ... (rest of the SQL statements)
    ]

    @classmethod
    def setUpClass(cls):
        try:
            pyodbc.connect('DRIVER={};SERVER=127.0.0.1:6667;DATABASE=root;UID=root;PWD=root'.format(Config.JDBC_DRIVER_NAME))
            importData()
        except Exception as e:
            print(e)
            fail()

    @classmethod
    def tearDownClass(cls):
        try:
            cleanEnv()
        except Exception as e:
            print(e)

    def test_select_with_star_test1(self):
        ret_array = ["1509465720000,qrcode003,qrcode002,"]
        try:
            conn = pyodbc.connect('DRIVER={};SERVER=127.0.0.1:6667;DATABASE=root;UID=root;PWD=root'.format(Config.JDBC_DRIVER_NAME))
            cursor = conn.cursor()
            has_resultset = cursor.execute("select qrcode from root.sgd1.* where qrcode in ('qrcode002', 'qrcode003')")
            self.assertTrue(has_resultset)
            result_set = cursor.fetchall()
            for row in result_set:
                expected_strings = ret_array[0].split(",")
                actual_builder = StringBuilder()
                for i, col in enumerate(row):
                    actual_builder.append(str(col)) + ","
                    if i == 1:  # Time column
                        continue
                    self.assertEqual(expected_strings[i-1], str(col))
        except Exception as e:
            print(e)
            fail()

    def test_select_with_star_test2(self):
        ret_array = ["1509465780000,qrcode004,qrcode003,qrcode002,"]
        try:
            conn = pyodbc.connect('DRIVER={};SERVER=127.0.0.1:6667;DATABASE=root;UID=root;PWD=root'.format(Config.JDBC_DRIVER_NAME))
            cursor = conn.cursor()
            has_resultset = cursor.execute("select qrcode from root.sgd.*.* where qrcode in ('qrcode002', 'qrcode003', 'qrcode004')")
            self.assertTrue(has_resultset)
            result_set = cursor.fetchall()
            for row in result_set:
                expected_strings = ret_array[0].split(",")
                actual_builder = StringBuilder()
                for i, col in enumerate(row):
                    actual_builder.append(str(col)) + ","
                    if i == 1:  # Time column
                        continue
                    self.assertEqual(expected_strings[i-1], str(col))
        except Exception as e:
            print(e)
            fail()

    def test_select_with_align_by_device_test(self):
        ret_array = [
            "1509465660000,root.sgd1.s1,qrcode002,", 
            # ... (rest of the expected results)
        ]
        try:
            conn = pyodbc.connect('DRIVER={};SERVER=127.0.0.1:6667;DATABASE=root;UID=root;PWD=root'.format(Config.JDBC_DRIVER_NAME))
            cursor = conn.cursor()
            has_resultset = cursor.execute("select qrcode from root.sgd.*.* where qrcode in ('qrcode002', 'qrcode004') align by device")
            self.assertTrue(has_resultset)
            result_set = cursor.fetchall()
            for row in result_set:
                expected_strings = ret_array[0].split(",")
                actual_builder = StringBuilder()
                for i, col in enumerate(row):
                    actual_builder.append(str(col)) + ","
                    if i == 1:  # Time column
                        continue
                    self.assertEqual(expected_strings[i-1], str(col))
        except Exception as e:
            print(e)
            fail()

    def check_header(self, result_set_metadata, expected_header_strings, expected_types):
        try:
            actual_index_to_expected_index_list = []
            for i in range(1, len(result_set_metadata.columns) + 1):
                type_index = None
                for j, col_name in enumerate(expected_header_strings.split(",")):
                    if col_name == result_set_metadata.get_column_name(i):
                        type_index = j
                        break
                self.assertIsNotNone(type_index)
                self.assertEqual(expected_types[type_index], result_set_metadata.get_column_type(i))
                actual_index_to_expected_index_list.append(type_index)
            return actual_index_to_expected_index_list
        except Exception as e:
            print(e)

if __name__ == '__main__':
    unittest.main()
