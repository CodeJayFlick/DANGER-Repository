import logging
from pyiotdb import IoTDBConnection
from pyiotdb.utils import EnvironmentUtils
from pyiotdb.exceptions import StorageGroupNotSetException
from typing import List

class IoTDBFlushQueryMergeIT:
    logger = logging.getLogger(__name__)

    sqls: List[str] = [
        "SET STORAGE GROUP TO root.vehicle.d0",
        "CREATE TIMESERIES root.vehicle.d0.s0 WITH DATATYPE=INT32, ENCODING=RLE",
        "insert into root.vehicle.d0(timestamp,s0) values(1,101)",
        "insert into root.vehicle.d0(timestamp,s0) values(2,198)",
        "insert into root.vehicle.d0(timestamp,s0) values(100,99)",
        "insert into root.vehicle.d0(timestamp,s0) values(101,99)",
        "insert into root.vehicle.d0(timestamp,s0) values(102,80)",
        "insert into root.vehicle.d0(timestamp,s0) values(103,99)",
        "insert into root.vehicle.d0(timestamp,s0) values(104,90)",
        "insert into root.vehicle.d0(timestamp,s0) values(105,99)",
        "insert into root.vehicle.d0(timestamp,s0) values(106,99)",
        "flush",
        "insert into root.vehicle.d0(timestamp,s0) values(2,10000)",
        "insert into root.vehicle.d0(timestamp,s0) values(50,10000)",
        "insert into root.vehicle.d0(timestamp,s0) values(1000,22222)"
    ]

    @classmethod
    def setUpClass(cls):
        logging.basicConfig(level=logging.INFO)
        EnvironmentUtils.closeStatMonitor()
        EnvironmentUtils.envSetUp()

        connection = IoTDBConnection("127.0.0.1:6667", "root", "root")
        statement = connection.createStatement()

        for sql in cls.sqls:
            try:
                statement.execute(sql)
            except Exception as e:
                cls.logger.error(f"insertData failed - {e}")

    @classmethod
    def tearDownClass(cls):
        EnvironmentUtils.cleanEnv()

    @classmethod
    def selectAllSQLTest(cls):
        connection = IoTDBConnection("127.0.0.1:6667", "root", "root")
        statement = connection.createStatement()
        
        try:
            hasResultSet = statement.execute("SELECT * FROM root.$$")
            assert hasResultSet

            result_set = statement.executeQuery("SELECT * FROM root.$$")

            i = 0
            while result_set.next():
                i += 1

            statement.execute("merge")
        except Exception as e:
            cls.logger.error(f"selectAllSQLTest failed - {e}")
            raise AssertionError(e.getMessage())

    @classmethod
    def testFlushGivenGroup(cls):
        connection = IoTDBConnection("127.0.0.1:6667", "root", "root")

        insert_template = "INSERT INTO root.group%d(timestamp, s1, s2, s3) VALUES (%d, %d, %f, %s)"

        try:
            statement = connection.createStatement()
            
            for i in range(1, 4):
                for j in range(10, 20):
                    statement.execute(insert_template % (i, j, j, j * 0.1, str(j)))

            statement.execute("FLUSH")
            
            for i in range(1, 4):
                for j in range(30):
                    statement.execute(insert_template % (i, j, j, j * 0.1, str(j)))
                    
            statement.execute("FLUSH root.group1 TRUE")
            statement.execute("FLUSH root.group2,root.group3 FALSE")

            result_set = statement.executeQuery("SELECT * FROM root.group1,root.group2,root.group3")

            i = 0
            while result_set.next():
                i += 1

            assert i == 30
        except Exception as e:
            cls.logger.error(f"testFlushGivenGroup failed - {e}")
            raise AssertionError(e.getMessage())

    @classmethod
    def testFlushGivenGroupNoData(cls):
        connection = IoTDBConnection("127.0.0.1:6667", "root", "root")

        try:
            statement = connection.createStatement()
            
            for i in range(3):
                statement.execute(f"SET STORAGE GROUP TO root.nodatagroup{i}")
                
            for i in range(3):
                statement.execute("FLUSH root.nodatagroup{}".format(i))
                
            statement.execute("FLUSH root.nodatagroup0,root.nodatagroup1")
        except Exception as e:
            cls.logger.error(f"testFlushGivenGroupNoData failed - {e}")
            raise AssertionError(e.getMessage())

    @classmethod
    def testFlushNotExistGroupNoData(cls):
        connection = IoTDBConnection("127.0.0.1:6667", "root", "root")

        try:
            statement = connection.createStatement()
            
            for i in range(3):
                statement.execute(f"SET STORAGE GROUP TO root.noexist.nodatagroup{i}")
                
            try:
                statement.execute(
                    f"FLUSH root.noexist.nodatagroup0,root.notExistGroup1,root.notExistGroup2")
            except StorageGroupNotSetException as e:
                assert isinstance(e.__cause__, SQLException)
        except Exception as e:
            cls.logger.error(f"testFlushNotExistGroupNoData failed - {e}")
            raise AssertionError(e.getMessage())
