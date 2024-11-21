Here is the translation of the Java code into Python:

```Python
import mysql.connector
from datetime import datetime

class IoTDBMultiSeriesIT:
    def __init__(self):
        self.testFlag = TestConstant.testFlag
        self.tsFileConfig = TSFileDescriptor.getInstance().getConfig()
        self.maxNumberOfPointsInPage = 0
        self.pageSizeInByte = 0
        self.groupSizeInByte = 0
        self.prevPartitionInterval = 0

    @classmethod
    def setUp(cls):
        EnvironmentUtils.closeStatMonitor()

        # use small page setting
        maxNumberOfPointsInPage = cls.tsFileConfig.getMaxNumberOfPointsInPage()
        pageSizeInByte = cls.tsFileConfig.getPageSizeInByte()
        groupSizeInByte = cls.tsFileConfig.getGroupSizeInByte()

        # new value
        cls.tsFileConfig.setMaxNumberOfPointsInPage(1000)
        cls.tsFileConfig.setPageSizeInByte(1024 * 150)
        cls.tsFileConfig.setGroupSizeInByte(1024 * 1000)
        IoTDBDescriptor.getInstance().getConfig().setMemtableSizeThreshold(1024 * 1000)
        prevPartitionInterval = IoTDBDescriptor.getInstance().getConfig().getPartitionInterval()
        IoTDBDescriptor.getInstance().getConfig().setPartitionInterval(100)

    @classmethod
    def tearDown(cls):
        # recovery value
        cls.tsFileConfig.setMaxNumberOfPointsInPage(cls.maxNumberOfPointsInPage)
        cls.tsFileConfig.setPageSizeInByte(cls.pageSizeInByte)
        cls.tsFileConfig.setGroupSizeInByte(cls.groupSizeInByte)
        EnvironmentUtils.cleanEnv()
        IoTDBDescriptor.getInstance().getConfig().setPartitionInterval(cls.prevPartitionInterval)

    @classmethod
    def insertData(cls):
        try:
            cnx = mysql.connector.connect(
                user='root',
                password='root',
                host='127.0.0.1',
                port=6667,
                database='iotdb'
            )
            cursor = cnx.cursor()

            for sql in TestConstant.create_sql:
                cursor.execute(sql)

            cursor.execute("SET STORAGE GROUP TO root.fans")
            cursor.execute("CREATE TIMESERIES root.fans.d0.s0 WITH DATATYPE=INT32, ENCODING=RLE")
            cursor.execute("CREATE TIMESERIES root.fans.d0.s1 WITH DATATYPE=INT64, ENCODING=RLE")

            for time in range(1, 1000):
                sql = f"insert into root.fans.d0 values({time},{time % 70})"
                cursor.execute(sql)
                sql = f"insert into root.fans.d0 values({time},{time % 40})"
                cursor.execute(sql)

            # buffwrite data, unsealed file
            for time in range(100000, 101000):
                sql = f"insert into root.vehicle.d0 values({time},{time % 20})"
                cursor.execute(sql)
                sql = f"insert into root.vehicle.d0 values({time},{time % 30})"
                cursor.execute(sql)

        except Exception as e:
            print(e.getMessage())
            fail()

    @classmethod
    def selectAllTest(cls):
        try:
            cnx = mysql.connector.connect(
                user='root',
                password='root',
                host='127.0.0.1',
                port=6667,
                database='iotdb'
            )
            cursor = cnx.cursor()
            hasResultSet = cursor.execute("select * from root.fans.d0")
            assert hasResultSet
            result = cursor.fetchall()
            for row in result:
                print(row)

        except Exception as e:
            print(e.getMessage())
            fail()

    @classmethod
    def selectAllFromVehicleTest(cls):
        try:
            cnx = mysql.connector.connect(
                user='root',
                password='root',
                host='127.0.0.1',
                port=6667,
                database='iotdb'
            )
            cursor = cnx.cursor()
            hasResultSet = cursor.execute("select * from root.vehicle.d0")
            assert hasResultSet
            result = cursor.fetchall()
            for row in result:
                print(row)

        except Exception as e:
            print(e.getMessage())
            fail()

    @classmethod
    def selectOneSeriesWithValueFilterTest(cls):
        try:
            cnx = mysql.connector.connect(
                user='root',
                password='root',
                host='127.0.0.1',
                port=6667,
                database='iotdb'
            )
            cursor = cnx.cursor()
            hasResultSet = cursor.execute("select s0 from root.vehicle.d0 where s0 >= 20")
            assert hasResultSet
            result = cursor.fetchall()
            for row in result:
                print(row)

        except Exception as e:
            print(e.getMessage())
            fail()

    @classmethod
    def seriesGlobalTimeFilterTest(cls):
        try:
            cnx = mysql.connector.connect(
                user='root',
                password='root',
                host='127.0.0.1',
                port=6667,
                database='iotdb'
            )
            cursor = cnx.cursor()
            hasResultSet = cursor.execute("select s0 from root.vehicle.d0 where time > 22987")
            assert hasResultSet
            result = cursor.fetchall()
            for row in result:
                print(row)

        except Exception as e:
            print(e.getMessage())
            fail()

    @classmethod
    def selectUnknownTimeSeries(cls):
        try:
            cnx = mysql.connector.connect(
                user='root',
                password='root',
                host='127.0.0.1',
                port=6667,
                database='iotdb'
            )
            cursor = cnx.cursor()
            hasResultSet = cursor.execute("select s10 from root.vehicle.d0 where s0 < 111")
            assert not hasResultSet

        except Exception as e:
            print(e.getMessage())

    @classmethod
    def selectWhereUnknownTimeSeriesFromRoot(cls):
        try:
            cnx = mysql.connector.connect(
                user='root',
                password='root',
                host='127.0.0.1',
                port=6667,
                database='iotdb'
            )
            cursor = cnx.cursor()
            hasResultSet = cursor.execute("select s10 from root.vehicle.d0 where root.vehicle.d0.s0 < 111 and root.vehicle.d0.s10 < 111")
            assert not hasResultSet

        except Exception as e:
            print(e.getMessage())

    @classmethod
    def testCreateTimeSeriesWithoutEncoding(cls):
        try:
            cnx = mysql.connector.connect(
                user='root',
                password='root',
                host='127.0.0.1',
                port=6667,
                database='iotdb'
            )
            cursor = cnx.cursor()

            cursor.execute("CREATE TIMESERIES root.ln.wf01.wt01.name WITH DATATYPE=TEXT")
            cursor.execute(
                "CREATE TIMESERIES root.ln.wf01.wt01.age WITH DATATYPE=INT32, ENCODING=RLE"
            )
            cursor.execute("CREATE TIMESERIES root.ln.wf01.wt01.salary WITH DATATYPE=INT64")

        except Exception as e:
            print(e.getMessage())
```

Note that this is a direct translation of the Java code into Python. The actual implementation may vary depending on your specific requirements and constraints.