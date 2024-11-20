import pyodbc
from datetime import datetime as dt

class IoTDBWithoutAllNullIT:
    dataSet = [
        "SET STORAGE GROUP TO root.testWithoutAllNull",
        "CREATE TIMESERIES root.testWithoutAllNull.d1.s1 WITH DATATYPE=INT32, ENCODING=PLAIN",
        "CREATE TIMESERIES root.testWithoutAllNull.d1.s2 WITH DATATYPE=BOOLEAN, ENCODING=PLAIN",
        "CREATE TIMESERIES root.testWithoutAllNull.d1.s3 WITH DATATYPE=DOUBLE, ENCODING=PLAIN",
        "INSERT INTO root.testWithoutAllNull.d1(timestamp,s1) VALUES(6, 26)",
        "INSERT INTO root.testWithoutAllNull.d1(timestamp,s2) VALUES(7, false)",
        "INSERT INTO root.testWithoutAllNull.d1(timestamp,s1,s2) VALUES(9, 29, true)",
        "flush",
        "INSERT INTO root.testWithoutAllNull.d1(timestamp,s1,s2) VALUES(10, 20, true)",
        "INSERT INTO root.testWithoutAllNull.d1(timestamp,s1,s2,s3) VALUES(11, 21, false, 11.1)",
        "INSERT INTO root.testWithoutAllNull.d1(timestamp,s1,s2) VALUES(12, 22, true)",
        "INSERT INTO root.testWithoutAllNull.d1(timestamp,s1,s2,s3) VALUES(13, 23, false, 33.3)",
        "INSERT INTO root.testWithoutAllNull.d1(timestamp,s1,s3) VALUES(14, 24, 44.4)",
        "INSERT INTO root.testWithoutAllNull.d1(timestamp,s2,s3) VALUES(15, true, 55.5)"
    ]

    @classmethod
    def setUp(cls):
        conn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER=127.0.0.1;PORT=6667;DATABASE=root;UID=root;PWD=root')
        cursor = conn.cursor()
        for sql in cls.dataSet:
            try:
                cursor.execute(sql)
                conn.commit()
            except Exception as e:
                print(e)

    @classmethod
    def tearDown(cls):
        IoTDBWithoutAllNullIT.setUp()

    @classmethod
    def without_all_null_test1(cls):
        retArray = ["6,20,true,null", "11,24,true,55.5"]
        conn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER=127.0.0.1;PORT=6667;DATABASE=root;UID=root;PWD=root')
        cursor = conn.cursor()
        try:
            hasResultSet = bool(cursor.execute("SELECT last_value(*) FROM root.testWithoutAllNull.d1 GROUP BY([1,21), 5ms) WITHOUT NULL ALL"))
            if not hasResultSet:
                return
            cnt = 0
            for row in cursor.fetchall():
                ans = f"{row[0]},{row[2]},{row[3]},{row[4]}"
                assertEquals(retArray[cnt], ans)
                cnt += 1
        except Exception as e:
            print(e)

    @classmethod
    def without_all_null_test2(cls):
        retArray = ["11,24,true,55.5"]
        conn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER=127.0.0.1;PORT=6667;DATABASE=root;UID=root;PWD=root')
        cursor = conn.cursor()
        try:
            hasResultSet = bool(cursor.execute("SELECT last_value(*) FROM root.testWithoutAllNull.d1 GROUP BY([1,21), 5ms) WITHOUT NULL ALL limit 1 offset 1"))
            if not hasResultSet:
                return
            cnt = 0
            for row in cursor.fetchall():
                ans = f"{row[0]},{row[2]},{row[3]},{row[4]}"
                assertEquals(retArray[cnt], ans)
                cnt += 1
        except Exception as e:
            print(e)

    @classmethod
    def without_all_null_test3(cls):
        retArray = ["11,24,true,55.5"]
        conn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER=127.0.0.1;PORT=6667;DATABASE=root;UID=root;PWD=root')
        cursor = conn.cursor()
        try:
            hasResultSet = bool(cursor.execute("SELECT last_value(*) FROM root.testWithoutAllNull.d1 GROUP BY([1,21), 5ms) WITHOUT NULL ANY"))
            if not hasResultSet:
                return
            cnt = 0
            for row in cursor.fetchall():
                ans = f"{row[0]},{row[2]},{row[3]},{row[4]}"
                assertEquals(retArray[cnt], ans)
                cnt += 1
        except Exception as e:
            print(e)

    @classmethod
    def without_all_null_test4(cls):
        retArray = ["11,root.testWithoutAllNull.d1,24,true,55.5"]
        conn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER=127.0.0.1;PORT=6667;DATABASE=root;UID=root;PWD=root')
        cursor = conn.cursor()
        try:
            hasResultSet = bool(cursor.execute("SELECT last_value(*) FROM root.testWithoutAllNull.d1 GROUP BY([1,21), 5ms) WITHOUT NULL ALL LIMIT 1 OFFSET 1 ALIGN BY DEVICE"))
            if not hasResultSet:
                return
            cnt = 0
            for row in cursor.fetchall():
                ans = f"{row[0]},{row[2]},{row[3]},{row[4]}"
                assertEquals(retArray[cnt], ans)
                cnt += 1
        except Exception as e:
            print(e)

    @classmethod
    def without_all_null_test5(cls):
        retArray = ["6,root.testWithoutAllNull.d1,20,true,null"]
        conn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER=127.0.0.1;PORT=6667;DATABASE=root;UID=root;PWD=root')
        cursor = conn.cursor()
        try:
            hasResultSet = bool(cursor.execute("SELECT last_value(*) FROM root.testWithoutAllNull.d1 GROUP BY([1,21), 5ms) ORDER BY TIME DESC WITHOUT NULL ALL LIMIT 1 OFFSET 1 ALIGN BY DEVICE"))
            if not hasResultSet:
                return
            cnt = 0
            for row in cursor.fetchall():
                ans = f"{row[0]},{row[2]},{row[3]},{row[4]}"
                assertEquals(retArray[cnt], ans)
                cnt += 1
        except Exception as e:
            print(e)

IoTDBWithoutAllNullIT.setUp()
IoTDBWithoutAllNullIT.without_all_null_test1()
IoTDBWithoutAllNullIT.without_all_null_test2()
IoTDBWithoutAllNullIT.without_all_null_test3()
IoTDBWithoutAllNullIT.without_all_null_test4()
IoTDBWithoutAllNullIT.without_all_null_test5()
