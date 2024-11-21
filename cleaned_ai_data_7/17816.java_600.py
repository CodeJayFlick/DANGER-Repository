import os
from unittest import TestCase
from io import StringIO
import pyodbc


class IoTDBCreateSnapshotIT(TestCase):

    def setUp(self):
        self.config = {'IOTDB_URL_PREFIX': 'jdbc:iotdb://127.0.0.1:6667/', 
                       'JDBC_DRIVER_NAME': 'org.apache.iotdb.jdbc.IoTDBDriver', 
                       'SCHEMA_DIR': '/path/to/schema/directory'}
        
    def tearDown(self):
        pass

    def test_create_snapshot(self):

        try:
            conn = pyodbc.connect('DRIVER={};SERVER=127.0.0.1;PORT=6667;DATABASE=root'.format(self.config['JDBC_DRIVER_NAME']), 
                                   user='root', password='root')
            
            cursor = conn.cursor()
            
            # test before creating snapshot
            self.check_show_timeseries(cursor)

            # create snapshot
            cursor.execute("CREATE SNAPSHOT FOR SCHEMA")
            snapshot_file_path = os.path.join(self.config['SCHEMA_DIR'], 'mtree-1.snapshot.bin')

            # test snapshot file exists
            assert os.path.exists(snapshot_file_path), "Snapshot file does not exist"

            # test snapshot content correct
            expected_snapshot_content = [
                "2,s0,,1,2,1,-1,0",
                "2,s1,,2,2,1,-1,0",
                "2,s2,,3,2,1,-1,0",
                "2,s3,,5,0,1,-1,0",
                "2,s4,,0,0,1,-1,0",
                "1,d0,9223372036854775807,5",
                "2,s0,,1,2,1,-1,0",
                "2,s1,,5,0,1,-1,0",
                "2,s2,,0,0,1,-1,0",
                "1,d1,9223372036854775807,3",
                "0,vehicle,2",
                "0,root,1"
            ]

            d0_plans = set()
            for i in range(6):
                d0_plans.add(MLogWriter.convert_from_string(expected_snapshot_content[i]))

            d1_plans = set()
            for i in range(6, 12):
                d1_plans.add(MLogWriter.convert_from_string(expected_snapshot_content[i]))

            with MLogReader(snapshot_file_path) as mlog_reader:
                i = 0
                while i < 6 and mlog_reader.has_next():
                    plan = mlog_reader.next()
                    self.assertTrue(plan in d0_plans)
                    i += 1

                self.assertTrue(i == 6)

                while i < 12 and mlog_reader.has_next():
                    plan = mlog_reader.next()
                    self.assertTrue(plan in d1_plans)
                    i += 1

                self.assertTrue(i == 12)

        except Exception as e:
            print(str(e))
            self.fail()

    def check_show_timeseries(self, cursor):
        has_result_set = cursor.execute("SHOW TIMESERIES")
        self.assertTrue(has_result_set)

        result_set = cursor.fetchall()
        cnt = len(result_set)
        self.assertEqual(8, cnt)


if __name__ == '__main__':
    import unittest
    suite = unittest.TestLoader().loadTestsFromTestCase(IoTDBCreateSnapshotIT)
    unittest.TextTestRunner(verbosity=2).run(suite)

