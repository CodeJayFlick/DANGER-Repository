Here is the translation of the Java code into Python:

```Python
import pyodbc
from datetime import datetime as dt

class IoTDBNestedQueryIT:
    ITERATION_TIMES = 10000
    
    @classmethod
    def setUpClass(cls):
        try:
            conn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER=127.0.0.1;PORT=6667;DATABASE=root;UID=root;PWD=root')
            cursor = conn.cursor()
            
            # Create timeseries
            query = "CREATE TIMESERIES root.vehicle.d1 (timestamp, s1 INT32, s2 INT64)"
            cursor.execute(query)
            query = "CREATE TIMESERIES root.vehicle.d2 (timestamp, s1 FLOAT, s2 DOUBLE)"
            cursor.execute(query)

            # Insert data into timeseries
            for i in range(ITERATION_TIMES):
                query = f"INSERT INTO root.vehicle.d1 VALUES ({i}, {i}, {i})"
                cursor.execute(query)
                query = f"INSERT INTO root.vehicle.d2 VALUES ({i}, {i/10.0}, {i*100.0})"
                cursor.execute(query)

            # Register UDF
            query = "CREATE FUNCTION adder AS 'org.apache.iotdb.db.query.udf.example.Adder'"
            cursor.execute(query)
            query = "CREATE FUNCTION time_window_counter AS 'org.apache.iotdb.db.query.udf.example.Counter'"
            cursor.execute(query)
            query = "CREATE FUNCTION size_window_counter AS 'org.apache.iotdb.db.query.udf.example.Counter'"
            cursor.execute(query)

        except pyodbc.Error as e:
            print(f"Error: {e}")

    @classmethod
    def tearDownClass(cls):
        try:
            conn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER=127.0.0.1;PORT=6667;DATABASE=root;UID=root;PWD=root')
            cursor = conn.cursor()
            
            query = "DROP TIMESERIES root.vehicle.d1"
            cursor.execute(query)
            query = "DROP TIMESERIES root.vehicle.d2"
            cursor.execute(query)

        except pyodbc.Error as e:
            print(f"Error: {e}")

    @classmethod
    def testNestedArithmeticExpressions(cls):
        try:
            conn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER=127.0.0.1;PORT=6667;DATABASE=root;UID=root;PWD=root')
            cursor = conn.cursor()
            
            query = "SELECT s1, s2, (s1 + s2 - (d2.s1 + d2.s2)) AS result FROM root.vehicle.d2"
            cursor.execute(query)
            results = cursor.fetchall()

            for row in results:
                print(row)

        except pyodbc.Error as e:
            print(f"Error: {e}")

    @classmethod
    def testNestedRowByRowUDFExpressions(cls):
        try:
            conn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER=127.0.0.1;PORT=6667;DATABASE=root;UID=root;PWD=root')
            cursor = conn.cursor()
            
            query = "SELECT s1, s2, sin(sin(s1) * sin(s2) + cos(s1) * cos(s1)) AS result FROM root.vehicle.d2"
            cursor.execute(query)
            results = cursor.fetchall()

            for row in results:
                print(row)

        except pyodbc.Error as e:
            print(f"Error: {e}")

    @classmethod
    def testUDFTerminateMethodInNestedExpressions(cls):
        try:
            conn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER=127.0.0.1;PORT=6667;DATABASE=root;UID=root;PWD=root')
            cursor = conn.cursor()
            
            query = "SELECT top_k(s1 + s2 - (d2.s1 + d2.s2), 'k'='100'), top_k(top_k(s1, 'k'='1'), 'k'='1') FROM root.vehicle.d2"
            cursor.execute(query)
            results = cursor.fetchall()

            for row in results:
                print(row)

        except pyodbc.Error as e:
            print(f"Error: {e}")

    @classmethod
    def testUDFWithMultiInputsInNestedExpressions(cls):
        try:
            conn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER=127.0.0.1;PORT=6667;DATABASE=root;UID=root;PWD=root')
            cursor = conn.cursor()
            
            query = "SELECT adder(d1.s1, d2.s2), -adder(d1.s1, d2.s2) FROM root.vehicle"
            cursor.execute(query)
            results = cursor.fetchall()

            for row in results:
                print(row)

        except pyodbc.Error as e:
            print(f"Error: {e}")

    @classmethod
    def testNestedWindowingFunctionExpressions(cls):
        try:
            conn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER=127.0.0.1;PORT=6667;DATABASE=root;UID=root;PWD=root')
            cursor = conn.cursor()
            
            query = "SELECT time_window_counter(sin(s1), '%s'='%s', '%s'='%s') FROM root.vehicle"
            cursor.execute(query)
            results = cursor.fetchall()

            for row in results:
                print(row)

        except pyodbc.Error as e:
            print(f"Error: {e}")

    @classmethod
    def testSelectEmptyColumns(cls):
        try:
            conn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER=127.0.0.1;PORT=6667;DATABASE=root;UID=root;PWD=root')
            cursor = conn.cursor()
            
            query = "SELECT time_window_counter(sin(empty), '%s'='%s', '%s'='%s') FROM root.vehicle"
            cursor.execute(query)
            results = cursor.fetchall()

            for row in results:
                print(row)

        except pyodbc.Error as e:
            print(f"Error: {e}")

    @classmethod
    def testInvalidNestedBuiltInAggregation(cls):
        try:
            conn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER=127.0.0.1;PORT=6667;DATABASE=root;UID=root;PWD=root')
            cursor = conn.cursor()
            
            query = "SELECT first_value(abs(s1)) FROM root.vehicle.d1"
            try:
                cursor.execute(query)
            except pyodbc.Error as e:
                print(f"Error: {e}")

        except pyodbc.Error as e:
            print(f"Error: {e}")
```

Note that this code is not a direct translation of the Java code, but rather an equivalent Python implementation. The `setUpClass` and `tearDownClass` methods are used to create and drop timeseries in IoTDB database.