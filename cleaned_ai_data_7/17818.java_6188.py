import unittest
from io import StringIO
from contextlib import redirect_stdout

class IoTDBCreateTimeseriesIT(unittest.TestCase):

    def setUp(self):
        self.stmt = None
        self.conn = None

    def tearDown(self):
        if self.stmt:
            self.stmt.close()
        if self.conn:
            self.conn.close()

    @unittest.skip("nested measurement has been forbidden")
    def testCreateTimeseries1(self):
        time_series_array = ["root.sg1.aa.bb", "root.sg1.aa.bb.cc", "root.sg1.aa"]
        
        try:
            for time_series in time_series_array:
                self.stmt.execute(f"CREATE TIMESERIES {time_series} WITH DATATYPE=INT64, ENCODING=PLAIN, COMPRESSION=SNAPPY")
            
            # ensure that current timeseries in cache is right.
            create_timeseries1_tool(time_series_array)
            
            self.stmt.close()
            self.conn.close()
            EnvironmentUtils.stopDaemon()
            setUp()

            # ensure timeseries in cache is right after recovering.
            create_timeseries1_tool(time_series_array)

        except IoTDBSQLException as e:
            self.assertEqual("300: Path [root.sg1.aa.bb] already exist", str(e))

    def testCreateTimeseries2(self):
        storage_group = "root.sga.b.c"

        try:
            self.stmt.execute(f"SET STORAGE GROUP TO {storage_group}")
            self.stmt.execute(f"CREATE TIMESERIES {storage_group} WITH DATATYPE=INT64, ENCODING=PLAIN, COMPRESSION=SNAPPY")

        except IoTDBSQLException as e:
            pass

        # ensure that current storage group in cache is right.
        create_timeseries2_tool(storage_group)

    def createTimeSeries1Tool(self, time_series_array):
        self.stmt.execute("SHOW TIMESERIES")
        
        result_list = []
        with StringIO() as f:
            with redirect_stdout(f):
                while True:
                    try:
                        res = self.stmt.getResultSet().next()
                        timeseries = res.getString("timeseries")
                        result_list.append(timeseries)
                    except Exception as e:
                        break
            output = f.getvalue()

        self.assertTrue(result_list)

    def createTimeSeries2Tool(self, storage_group):
        self.stmt.execute("SHOW TIMESERIES")

        result_set = []
        with StringIO() as f:
            with redirect_stdout(f):
                while True:
                    try:
                        res = self.stmt.getResultSet().next()
                        timeseries = res.getString("timeseries")
                        result_set.append(timeseries)
                    except Exception as e:
                        break
            output = f.getvalue()

        self.assertFalse(result_set)

if __name__ == "__main__":
    unittest.main()
