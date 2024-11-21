import mysql.connector
from io import StringIO

class IoTDBFuzzyQueryIT:

    def __init__(self):
        self.sqls = []
        self.connection = None

    @classmethod
    def setUpClass(cls):
        EnvironmentUtils.closeStatMonitor()
        cls.init_create_sql_statement()
        EnvironmentUtils.env_set_up()

    @classmethod
    def tearDownClass(cls):
        if cls.connection is not None:
            try:
                cls.connection.close()
            except Exception as e:
                print(e)

    def close(self):
        if self.connection is not None:
            try:
                self.connection.close()
            except Exception as e:
                print(e)

    @classmethod
    def init_create_sql_statement(cls):
        cls.sqls.append("SET STORAGE GROUP TO root.t1")
        cls.sqls.append(
            "CREATE TIMESERIES root.t1.wf01.wt01.status WITH DATATYPE=TEXT, ENCODING=PLAIN"
        )
        cls.sqls.append(
            "CREATE TIMESERIES root.t1.wf01.wt01.temperature WITH DATATYPE=FLOAT, ENCODING=RLE"
        )

    @classmethod
    def insert_data(cls):
        try:
            cnx = mysql.connector.connect(user='root', password='root',
                                           host='127.0.0.1',
                                           database='iotdb')
            cursor = cnx.cursor()
            for sql in cls.sqls:
                cursor.execute(sql)
            cursor.close()
            cnx.close()
        except Exception as e:
            print(e)

    @classmethod
    def test_like(cls):
        try:
            st0 = self.connection.cursor()
            has_resultset = st0.execute(
                "SELECT status FROM root.t1.wf01.wt01 WHERE status LIKE '1%'"
            )
            assert has_resultset

            result_str = ""
            while True:
                row = st0.fetchone()
                if row is None:
                    break
                result_str += str(row[0]) + ","

            print(result_str)

        except Exception as e:
            print(e)

    @classmethod
    def test_like_non_text_column(cls):
        try:
            st1 = self.connection.cursor()
            st1.execute(
                "SELECT * FROM root.t1.wf01.wt01 WHERE temperature LIKE '1%'"
            )
        except Exception as e:
            print(e)

    @classmethod
    def output_result_str(cls, resultset):
        result_builder = StringIO()
        while True:
            row = resultset.fetchone()
            if row is None:
                break
            result_builder.write(str(row[0]) + ",")

        return result_builder.getvalue().strip()

    @classmethod
    def check_header(cls, resultset_metadata, expected_headers, expected_types):
        actual_index_to_expected_index_list = []
        for i in range(len(expected_headers)):
            type_index = None
            for j in range(1, resultset_metadata.column_count + 1):
                if str(resultset_metadata.get_column_name(j)) == expected_headers[i]:
                    type_index = expected_types.index(resultset_metadata.get_column_type(j))
                    break

            assert type_index is not None
            actual_index_to_expected_index_list.append(type_index)

        return actual_index_to_expected_index_list

    @classmethod
    def select_like_align_by_device(cls):
        try:
            cnx = mysql.connector.connect(user='root', password='root',
                                           host='127.0.0.1',
                                           database='iotdb')
            cursor = cnx.cursor()
            has_resultset = cursor.execute(
                "SELECT status FROM root.t1.wf01.wt0* WHERE status LIKE '14%' align by device"
            )
            assert has_resultset

            resultset = cursor.fetchall()

            actual_index_to_expected_index_list = cls.check_header(resultset_metadata=cursor.description,
                                                                     expected_headers="Time,Device,status,", 
                                                                     expected_types=[mysql.connector.types.TIMESTAMP, mysql.connector.types.VARCHAR, mysql.connector.types.VARCHAR])

            cnt = 0
            for row in resultset:
                print(row)

        except Exception as e:
            print(e)
