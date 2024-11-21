import pyodbc
from unittest import TestCase


class PrecisionTest(TestCase):

    def setUp(self):
        self.env_setup()

    def tearDown(self):
        self.clean_env()

    def test_double_precision1(self):
        try:
            conn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER=127.0.0.1;PORT=6667;DATABASE=root;UID=root;PWD=root')
            cursor = conn.cursor()
            cursor.execute("SET STORAGE GROUP TO root.turbine1")
            cursor.execute("CREATE TIMESERIES root.turbine1.d1.s1 WITH DATATYPE=DOUBLE, ENCODING=PLAIN, COMPRESSION=SNAPPY")
            cursor.execute("INSERT INTO root.turbine1.d1 (TIMESTAMP, S1) VALUES (1, 1.2345678)")
            cursor.execute("SELECT * FROM root.turbine1.*")

            result = cursor.fetchall()
            for row in result:
                self.assertEqual(str(1.2345678), str(row[2]))

        except pyodbc.Error as e:
            print(e)

    def test_double_precision2(self):
        try:
            conn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER=127.0.0.1;PORT=6667;DATABASE=root;UID=root;PWD=root')
            cursor = conn.cursor()
            cursor.execute("SET STORAGE GROUP TO root.turbine1")
            cursor.execute("CREATE TIMESERIES root.turbine1.d1.s1 WITH DATATYPE=DOUBLE, ENCODING=RLE, COMPRESSION=SNAPPY")
            cursor.execute("INSERT INTO root.turbine1.d1 (TIMESTAMP, S1) VALUES (1, 1.2345678)")
            cursor.execute("SELECT * FROM root.turbine1.*")

            result = cursor.fetchall()
            for row in result:
                self.assertEqual(str(1.23), str(row[2]))

        except pyodbc.Error as e:
            print(e)

    def test_float_precision1(self):
        try:
            conn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER=127.0.0.1;PORT=6667;DATABASE=root;UID=root;PWD=root')
            cursor = conn.cursor()
            cursor.execute("SET STORAGE GROUP TO root.turbine1")
            cursor.execute("CREATE TIMESERIES root.turbine1.d1.s1 WITH DATATYPE=FLOAT, ENCODING=PLAIN, COMPRESSION=SNAPPY")
            cursor.execute("INSERT INTO root.turbine1.d1 (TIMESTAMP, S1) VALUES (1, 1.2345678)")
            cursor.execute("SELECT * FROM root.turbine1.*")

            result = cursor.fetchall()
            for row in result:
                self.assertEqual(str(1.2345678), str(row[2]))

        except pyodbc.Error as e:
            print(e)

    def test_float_precision2(self):
        try:
            conn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER=127.0.0.1;PORT=6667;DATABASE=root;UID=root;PWD=root')
            cursor = conn.cursor()
            cursor.execute("SET STORAGE GROUP TO root.turbine1")
            cursor.execute("CREATE TIMESERIES root.turbine1.d1.s1 WITH DATATYPE=FLOAT, ENCODING=RLE, COMPRESSION=SNAPPY")
            cursor.execute("INSERT INTO root.turbine1.d1 (TIMESTAMP, S1) VALUES (1, 1.2345678)")
            cursor.execute("SELECT * FROM root.turbine1.*")

            result = cursor.fetchall()
            for row in result:
                self.assertEqual(str(1.23), str(row[2]))

        except pyodbc.Error as e:
            print(e)

    def env_setup(self):
        pass

    def clean_env(self):
        pass
