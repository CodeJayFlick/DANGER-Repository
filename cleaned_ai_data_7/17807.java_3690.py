import pyodbc
from datetime import datetime as dt
import math

class IoTDBArithmeticIT:
    E = 0.0001
    INSERTION_SQLS = [
        "insert into root.sq.d1(time, s1, s2, s3, s4, s5, s6, s7) values (1, 1, 1, 1, 1, False, '1', 1)",
        "insert into root.sq.d1(time, s1, s2, s3, s4, s5, s6, s8) values (2, 2, 2, 2, 2, False, '2', 2)",
        "insert into root.sq.d1(time, s1, s2, s3, s4, s5, s6, s7) values (3, 3, 3, 3, 3, True, '3', 3)",
        "insert into root.sq.d1(time, s1, s2, s3, s4, s5, s6, s8) values (4, 4, 4, 4, 4, True, '4', 4)",
        "insert into root.sq.d1(time, s1, s2, s3, s4, s5, s6, s7, s8) values (5, 5, 5, 5, 5, True, '5', 5, 5)"
    ]

    def setUp(self):
        envSetUp()
        self.createTimeSeries()

    def createTimeSeries(self):
        IoTDB.metaManager.setStorageGroup(PartialPath("root.sq"))
        for i in range(8):
            IoTDB.metaManager.createTimeseries(
                PartialPath(f"root.sq.d1.s{i+1}"),
                TSDataType.INT32 if i < 4 else TSDataType.FLOAT,
                TSEncoding.PLAIN, CompressionType.UNCOMPRESSED, None
            )

    def generateData(self):
        conn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER=127.0.0.1;PORT=6667;DATABASE=root;UID=root;PWD=root')
        cursor = conn.cursor()
        for sql in INSERTION_SQLS:
            try:
                cursor.execute(sql)
                conn.commit()
            except pyodbc.Error as e:
                print(f"Error: {e}")
        conn.close()

    def tearDown(self):
        cleanEnv()

    @staticmethod
    def testArithmeticBinary():
        conn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER=127.0.0.1;PORT=6667;DATABASE=root;UID=root;PWD=root')
        cursor = conn.cursor()
        operands = ["s1", "s2", "s3", "s4"]
        operators = [" + ", " - ", " * ", " / ", "%"]
        for operator in operators:
            expressions = [f"{left} {operator} {right}" for left in operands for right in operands]
            sql = f"SELECT {', '.join(expressions)} FROM root.sq.d1"
            cursor.execute(sql)
            result = cursor.fetchall()
            assert len(result) == 16
            for row in result:
                for i, value in enumerate(row):
                    if operator == " + ": expected = sum([int(x) for x in operands]) * (i % 2 == 0)
                    elif operator == " - ": expected = sum([int(x) for x in operands]) * (i % 2 != 0)
                    elif operator == " * ": expected = int(operands[0]) ** i
                    elif operator == " / ": expected = int(operands[0]) // i
                    else: expected = int(operands[0]) % i
                    assert math.isclose(value, expected), f"Expected {expected}, got {value}"
        conn.close()

    @staticmethod
    def testArithmeticUnary():
        conn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER=127.0.0.1;PORT=6667;DATABASE=root;UID=root;PWD=root')
        cursor = conn.cursor()
        expressions = ["- s1", "- s2", "- s3", "- s4"]
        sql = f"SELECT {', '.join(expressions)} FROM root.sq.d1"
        cursor.execute(sql)
        result = cursor.fetchall()
        assert len(result) == 16
        for row in result:
            for i, value in enumerate(row):
                if expressions[i].startswith("-"):
                    expected = -int(INSERTION_SQLS[0].split(",")[i+2])
                else: expected = int(INSERTION_SQLS[0].split(",")[i+2])
                assert math.isclose(value, expected), f"Expected {expected}, got {value}"
        conn.close()

    @staticmethod
    def testHybridQuery():
        conn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER=127.0.0.1;PORT=6667;DATABASE=root;UID=root;PWD=root')
        cursor = conn.cursor()
        expressions = ["s1", "s1 + s2", f"sin({INSERTION_SQLS[0].split(',')[3]})"]
        sql = f"SELECT {', '.join(expressions)} FROM root.sq.d1"
        cursor.execute(sql)
        result = cursor.fetchall()
        assert len(result) == 16
        for row in result:
            for i, value in enumerate(row):
                if expressions[i].startswith("s"):
                    expected = int(INSERTION_SQLS[0].split(",")[i+2])
                elif expressions[i] == "sin(s1)": expected = math.sin(int(INSERTION_SQLS[0].split(',')[3]))
                else: expected = float(expressions[i].replace(' + ', '+').replace(' - ', '-'))
                assert math.isclose(value, expected), f"Expected {expected}, got {value}"
        conn.close()

    @staticmethod
    def testNonAlign():
        conn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER=127.0.0.1;PORT=6667;DATABASE=root;UID=root;PWD=root')
        cursor = conn.cursor()
        try:
            result = cursor.execute("SELECT s7 + s8 FROM root.sq.d1").fetchall()[0]
            assert math.isclose(result[0], 10), f"Expected {10}, got {result}"
        except pyodbc.Error as e:
            print(f"Error: {e}")
        conn.close()

    @staticmethod
    def testWrongTypeBoolean():
        try:
            cursor.execute("SELECT s1 + s5 FROM root.sq.d1")
        except pyodbc.Error as e:
            assert "Unsupported data type: BOOLEAN" in str(e)

    @staticmethod
    def testWrongTypeText():
        try:
            cursor.execute("SELECT s1 + s6 FROM root.sq.d1")
        except pyodbc.Error as e:
            assert "Unsupported data type: TEXT" in str(e)
