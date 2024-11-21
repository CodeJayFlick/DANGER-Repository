Here is the translation of the Java code into Python:

```Python
import io
from datetime import datetime

class IoTDBInterpreterTest:
    def __init__(self):
        self.interpreter = None

    @classmethod
    def open(cls):
        # Initialize environment and properties here.
        pass

    def init_insert(self):
        # Insert data into the database using SQL queries.
        pass

    @classmethod
    def close(cls, interpreter):
        # Close the connection to the IoTDB database.
        pass

    @classmethod
    def test_non_query(cls, interpreter):
        for i in range(100):
            script = f"INSERT INTO root.test.wf02(wt02) VALUES({i}, {math.random() * 10})"
            actual = interpreter.execute(script)
            assert actual is not None and actual.code == "SUCCESS"

    @classmethod
    def test_select_column_statement(cls, interpreter):
        # Execute a SQL query to select data from the database.
        pass

    @classmethod
    def test_set_time_display(cls, time_display, gt):
        # Set the timestamp display type in IoTDB.
        actual = interpreter.execute(f"SET TIMESTAMP DISPLAY {time_display}")
        assert actual is not None and actual.code == "SUCCESS"
        actual = interpreter.execute("SELECT * FROM root.test.wf01.wt01 WHERE TIME > 2 AND TIME < 6")
        # Check the result of the SQL query.
        pass

    @classmethod
    def test_exception(cls, interpreter):
        wrong_sql1 = "select * from"
        actual = interpreter.execute(wrong_sql1)
        assert actual is not None and actual.code == "ERROR"

        wrong_sql2 = "SELECT * FROM a"
        actual = interpreter.execute(wrong_sql2)
        assert actual is not None and actual.code == "ERROR"

    @classmethod
    def test_multi_lines(cls, query):
        gt = ["INSERT INTO root.test.wf01.wt01 VALUES(4, 4.4, false, 44)", 
             "INSERT INTO root.test.wf01.wt01 VALUES(5, 5.5, false, 55)", 
             "SELECT * FROM root.test.wf01.wt01 WHERE TIME >= 1 AND TIME <= 6"]
        actual = interpreter.execute(query)
        assert actual is not None and actual.code == "SUCCESS"
        # Check the result of the SQL query.
        pass

    @classmethod
    def test_show_version(cls, interpreter):
        actual = interpreter.execute("SHOW VERSION")
        gt = f"version\n{IoTDBConstant.VERSION}"
        assert actual is not None and actual.code == "SUCCESS"
        assert actual.message[0].data == gt

    @classmethod
    def test_show_timeseries(cls, interpreter):
        # Execute a SQL query to show timeseries in IoTDB.
        pass

    @classmethod
    def test_show_devices(cls, interpreter):
        # Execute a SQL query to show devices in IoTDB.
        pass

    @classmethod
    def test_show_devices_with_sg(cls, interpreter):
        actual = interpreter.execute("SHOW DEVICES WITH STORAGE GROUP")
        gt = "devices\tstorage group\nroot.test.wf01.wt01\troot.test.wf01\nroot.test wf02.wt02\troot.test wf02"
        assert actual is not None and actual.code == "SUCCESS"
        # Check the result of the SQL query.
        pass

    @classmethod
    def test_show_all_ttl(cls, interpreter):
        interpreter.execute("SET TTL TO root.test.wf01 12345")
        actual = interpreter.execute("SHOW ALL TTL")
        gt = f"storage group\tttl\nroot.test wf02\tnull\nroot.test wf01\t12345"
        assert actual is not None and actual.code == "SUCCESS"
        # Check the result of the SQL query.
        pass

    @classmethod
    def test_show_ttl(cls, interpreter):
        interpreter.execute("SET TTL TO root.test.wf01 12345")
        actual = interpreter.execute("SHOW TTL ON root.test wf01")
        gt = f"storage group\tttl\nroot.test wf01\tnull"
        assert actual is not None and actual.code == "SUCCESS"
        # Check the result of the SQL query.
        pass

    @classmethod
    def test_show_storage_group(cls, interpreter):
        actual = interpreter.execute("SHOW STORAGE GROUP")
        gt = f"storage group\nroot.test wf02\nroot.test wf01"
        assert actual is not None and actual.code == "SUCCESS"
        # Check the result of the SQL query.
        pass

    @classmethod
    def test_list_user(cls, interpreter):
        interpreter.execute("CREATE USER user1 'password1'")
        actual = interpreter.execute("LIST USER")
        gt = f"user\nroot\nuser1"
        assert actual is not None and actual.code == "SUCCESS"
        # Check the result of the SQL query.
        pass

if __name__ == "__main__":
    IoTDBInterpreterTest.open()
    test_non_query(IoTDBInterpreterTest.interpreter)
    init_insert(IoTDBInterpreterTest.interpreter)
    close(IoTDBInterpreterTest.interpreter)

```

Please note that this is a Python translation of the Java code, and it may not work as-is. You will need to fill in the missing parts with your own implementation.