import unittest
from datetime import datetime

class EngineDataSetWithValueFilterTest(unittest.TestCase):

    def setUp(self):
        self.sqls = [
            "SET STORAGE GROUP TO root.vehicle",
            "SET STORAGE GROUP TO root.test",
            "CREATE TIMESERIES root.vehicle.d0.s0 WITH DATATYPE=INT32, ENCODING=RLE",
            "CREATE TIMESERIES root.vehicle.d0.s1 WITH DATATYPE=TEXT, ENCODING=PLAIN",
            "CREATE TIMESERIES root.test.d0.s0 WITH DATATYPE=INT32, ENCODING=RLE",
            "CREATE TIMESERIES root.test.d0.s1 WITH DATATYPE=TEXT, ENCODING=PLAIN",
            "insert into root.vehicle.d0(timestamp,s0) values(10,100)",
            # ... and so on
        ]

    def tearDown(self):
        pass

    def testHasNextAndNext(self):
        query_plan = processor.parse_sql_to_physical_plan("select test.d0.s1 from root where root.vehicle.d0.s0 > 100")
        data_set = query_executor.process_query(query_plan, EnvironmentUtils.TEST_QUERY_CONTEXT)
        self.assertTrue(data_set.has_next())
        self.assertEqual(str(next(data_set)), "16\t109")
        self.assertTrue(data_set.has_next())
        self.assertEqual(str(next(data_set)), "20\129")
        self.assertFalse(data_set.has_next())

    def testOrderByTimeDesc(self):
        query_plan = processor.parse_sql_to_physical_plan("select vehicle.d0.s1 from root where root.vehicle.d0.s0 > 100 order by time desc")
        data_set = query_executor.process_query(query_plan, EnvironmentUtils.TEST_QUERY_CONTEXT)
        self.assertTrue(data_set.has_next())
        self.assertEqual(str(next(data_set)), "206\t132")
        # ... and so on

if __name__ == '__main__':
    unittest.main()
