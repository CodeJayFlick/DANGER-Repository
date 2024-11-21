Here is the translation of the Java code into Python:

```Python
import mysql.connector
from datetime import datetime as dt

class IoTDBOverlappedPageIT:
    before_max_number_of_points_in_page = None

    data_set1 = [
        "SET STORAGE GROUP TO root.sg1",
        "CREATE TIMESERIES root.sg1.d1.s1 WITH DATATYPE=INT32, ENCODING=PLAIN",
        "INSERT INTO root.sg1.d1(time,s1) VALUES(1, 1)",
        "INSERT INTO root.sg1.d1(time,s1) VALUES(10, 10)",
        "flush",
        "INSERT INTO root.sg1.d1(time,s1) VALUES(20, 20)",
        "INSERT INTO root.sg1.d1(time,s1) VALUES(30, 30)",
        "flush",
        "INSERT INTO root.sg1.d1(time,s1) VALUES(110, 110)",
        "flush",
        "INSERT INTO root.sg1.d1(time,s1) VALUES(5, 5)",
        "INSERT INTO root.sg1.d1(time,s1) VALUES(50, 50)",
        "INSERT INTO root.sg1.d1(time,s1) VALUES(100, 100)",
        "flush",
        "INSERT INTO root.sg1.d1(time,s1) VALUES(15, 15)",
        "INSERT INTO root.sg1.d1(time,s1) VALUES(25, 25)",
        "flush"
    ]

    @classmethod
    def setUp(cls):
        cls.before_max_number_of_points_in_page = TSFileDescriptor.getInstance().getConfig().getMaxNumberOfPointsInPage()
        TSFileDescriptor.getInstance().getConfig().setMaxNumberOfPointsInPage(10)
        EnvironmentUtils.envSetUp()

    @classmethod
    def tearDown(cls):
        EnvironmentUtils.cleanEnv()
        IoTDBDescriptor.getInstance().getConfig().setMemtableSizeThreshold(cls.before_max_number_of_points_in_page)

    @classmethod
    def selectOverlappedPageTest1(cls):
        res = [
            "11,111", 
            "12,112", 
            "13,113", 
            "14,114", 
            "15,115", 
            "16,116", 
            "17,117", 
            "18,118", 
            "19,119",
            "20,120"
        ]

        try:
            cnx = mysql.connector.connect(
                user='root',
                password='root',
                host='127.0.0.1',
                port=6667,
                database='iotdb'
            )
            cursor = cnx.cursor()

            for insert_sql in cls.data_set1:
                cursor.execute(insert_sql)

            sql = "SELECT s0 FROM root.vehicle.d0 WHERE time >= 1 AND time <= 110 AND root.vehicle.d0.s0 > 110"
            try:
                cursor.execute(sql)
                result = cursor.fetchall()
                cnt = 0
                for row in result:
                    ans = str(row[0]) + "," + str(row[1])
                    assert res[cnt] == ans, f"Expected {res[cnt]} but got {ans}"
                    cnt += 1
            except Exception as e:
                print(str(e))
                raise

        except Exception as e:
            print(str(e))
            raise

    @classmethod
    def selectOverlappedPageTest2(cls):
        res = ["0,10"]

        try:
            cnx = mysql.connector.connect(
                user='root',
                password='root',
                host='127.0.0.1',
                port=6667,
                database='iotdb'
            )
            cursor = cnx.cursor()

            for insert_sql in cls.data_set1:
                cursor.execute(insert_sql)

            has_resultset = cursor.execute("SELECT count(s1) FROM root.sg1.d1")
            assert has_resultset, "Expected a result set but got None"
            cnt = 0
            try:
                result = cursor.fetchall()
                for row in result:
                    ans = str(row[0]) + "," + str(row[1])
                    assert res[cnt] == ans, f"Expected {res[cnt]} but got {ans}"
                    cnt += 1
                assert len(res) == cnt, "Length of expected and actual results do not match"
            except Exception as e:
                print(str(e))
                raise

        except Exception as e:
            print(str(e))
            raise

    @classmethod
    def insert_data(cls):
        try:
            cnx = mysql.connector.connect(
                user='root',
                password='root',
                host='127.0.0.1',
                port=6667,
                database='iotdb'
            )
            cursor = cnx.cursor()

            cursor.execute("CREATE TIMESERIES root.vehicle.d0.s0 WITH DATATYPE=INT32, ENCODING=RLE")

            for time in range(1, 11):
                sql = f"INSERT INTO root.vehicle.d0(timestamp,s0) VALUES({time},{time})"
                cursor.execute(sql)

            cursor.execute("flush")

            for time in range(11, 21):
                sql = f"INSERT INTO root.vehicle.d0(timestamp,s0) VALUES({time},{time+100})"
                cursor.execute(sql)

            for time in range(100, 121):
                sql = f"INSERT INTO root.vehicle.d0(timestamp,s0) VALUES({time},{time})"
                cursor.execute(sql)

            cursor.execute("flush")

        except Exception as e:
            print(str(e))
            raise

IoTDBOverlappedPageIT.setUp()
IoTDBOverlappedPageIT.selectOverlappedPageTest1()
IoTDBOverlappedPageIT.insert_data()
IoTDBOverlappedPageIT.tearDown()