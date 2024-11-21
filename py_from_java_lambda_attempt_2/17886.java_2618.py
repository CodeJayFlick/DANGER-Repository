Here is the equivalent Python code:

```Python
import pyodbc
from datetime import datetime, timedelta

class IoTDBTimePartitionIT:
    def __init__(self):
        self.prev_partition_interval = None

    def setUp(self):
        # Set up environment for testing
        pass  # This part of the original Java code is not implemented in Python

    def tearDown(self):
        # Clean up after test
        pass  # This part of the original Java code is not implemented in Python

    def testOrderByTimeDesc(self):
        try:
            conn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER=localhost;PORT=1433;DATABASE=mydatabase;UID=root;PWD=root')
            cursor = conn.cursor()

            # Insert data into the database
            sqls = [
                "INSERT INTO root.group_1.d_1 (timestamp, s_1) VALUES ('2018-07-18T00:00:00.000+08:00', 18.0)",
                "INSERT INTO root.group_1.d_1 (timestamp, s_1) VALUES ('2018-07-19T00:00:00.000+08:00', 19.0)",
                "INSERT INTO root.group_1.d_1 (timestamp, s_1) VALUES ('2019-08-19T00:00:00.000+08:00', 20.0)"
            ]
            for sql in sqls:
                cursor.execute(sql)

            # Execute query to test order by time desc
            ret_array = ["20.0", "19.0", "18.0"]
            has_resultset = True

            try:
                cursor.execute("SELECT * FROM root.group_1.d_1 ORDER BY timestamp DESC")
                result = cursor.fetchall()
                for row in result:
                    ans = str(row[2])  # Assuming the third column is s_1
                    assert ret_array.pop(0) == ans, "Failed to get expected results"
            except Exception as e:
                print(str(e))
                raise

        finally:
            conn.close()

# Create an instance of IoTDBTimePartitionIT and run testOrderByTimeDesc method
iotdb_time_partition_it = IoTDBTimePartitionIT()
iotdb_time_partition_it.testOrderByTimeDesc()
```

Please note that this Python code is not a direct translation from the original Java code. It's more like a rewritten version in Python, with some parts missing (like `setUp` and `tearDown`) because they are specific to the environment setup of IoTDB which might be different for Python.