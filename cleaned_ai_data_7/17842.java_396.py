import pyodbc
from datetime import datetime as dt

class IoTDBInsertNaNIT:
    CREATE_TEMPLATE_SQL = "CREATE TIMESERIES root.vehicle.%s.%s WITH DATATYPE=%s, ENCODING=%s, MAX_POINT_NUMBER=%d"
    INSERT_TEMPLATE_SQL = "INSERT INTO root.vehicle.%s( timestamp, %s) VALUES(%d, '%s')"
    INSERT_BRAND_NEW_TEMPLATE_SQL = "INSERT INTO root.cycle.%s(timestamp, %s) VALUES(%d, '%s')"

    sqls = []
    TIMESTAMP = 10
    VALUE = 'NaN'
    DELTA_FLOAT = 0.0000001f
    DELTA_DOUBLE = 0.0000001d

    @classmethod
    def setUpClass(cls):
        EnvironmentUtils.closeStatMonitor()
        cls.initCreateSQLStatement()
        EnvironmentUtils.envSetUp()
        cls.insertData()

    @classmethod
    def tearDownClass(cls):
        EnvironmentUtils.cleanEnv()

    @classmethod
    def initCreateSQLStatement(cls):
        sqls.append("SET STORAGE GROUP TO root.vehicle.f0")
        sqls.append("SET STORAGE GROUP TO root.vehicle.d0")
        for i in range(10):
            sqls.append(
                cls.CREATE_TEMPLATE_SQL % ("f0", "s" + str(i) + "rle", 'FLOAT', 'RLE', i)
            )
            sqls.append(
                cls.CREATE_TEMPLATE_SQL
                % ("f0", "s" + str(i) + "2f", 'FLOAT', 'TS_2DIFF', i)
            )
            sqls.append(
                cls.CREATE_TEMPLATE_SQL % ("d0", "s" + str(i) + "rle", 'DOUBLE', 'RLE', i)
            )
            sqls.append(
                cls.CREATE_TEMPLATE_SQL
                % ("d0", "s" + str(i) + "2f", 'DOUBLE', 'TS_2DIFF', i)
            )

        for i in range(10):
            sqls.append(cls.INSERT_TEMPLATE_SQL % ("f0", "s" + str(i) + "rle", TIMESTAMP, VALUE))
            sqls.append(
                cls.INSERT_TEMPLATE_SQL
                % ("f0", "s" + str(i) + "2f", TIMESTAMP, VALUE)
            )
            sqls.append(cls.INSERT_TEMPLATE_SQL % ("d0", "s" + str(i) + "rle", TIMESTAMP, VALUE))
            sqls.append(
                cls.INSERT_TEMPLATE_SQL
                % ("d0", "s" + str(i) + "2f", TIMESTAMP, VALUE)
            )

    @classmethod
    def insertData(cls):
        try:
            conn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER=127.0.0.1;PORT=6667;DATABASE=root;UID=root;PWD=root')
            cursor = conn.cursor()
            for sql in cls.sqls:
                cursor.execute(sql)
        except Exception as e:
            print(str(e))

    @classmethod
    def selectAllSQLTest(cls):
        try:
            conn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER=127.0.0.1;PORT=6667;DATABASE=root;UID=root;PWD=root')
            cursor = conn.cursor()
            hasResultSet = cursor.execute("SELECT * FROM root.vehicle.*")
            assert hasResultSet
            cnt = 0
            result = cursor.fetchall()
            for row in result:
                print(row)
        except Exception as e:
            print(str(e))

    @classmethod
    def selectTest(cls):
        try:
            conn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER=127.0.0.1;PORT=6667;DATABASE=root;UID=root;PWD=root')
            cursor = conn.cursor()
            cursor.execute(
                "CREATE TIMESERIES root.happy.device1.sensor1.temperature WITH DATATYPE=DOUBLE, ENCODING=RLE"
            )
            cursor.execute("INSERT INTO root.happy.device1. sensor1(timestamp, temperature) VALUES(7925, NaN)")
            hasResultSet = cursor.execute("SELECT * FROM root.happy.device1.sensor1")
            assert hasResultSet
        except Exception as e:
            print(str(e))

    @classmethod
    def testNaNValue(cls):
        try:
            conn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER=127.0.0.1;PORT=6667;DATABASE=root;UID=root;PWD=root')
            cursor = conn.cursor()
            cursor.execute(
                cls.INSERT_BRAND_NEW_TEMPLATE_SQL % ("d0", "s0" + "2f", TIMESTAMP, VALUE)
            )
            hasResultSet = cursor.execute("SHOW TIMESERIES")
            assert hasResultSet
        except Exception as e:
            print(str(e))
