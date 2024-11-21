Here is the translation of the Java code into Python:

```Python
import logging.config
from unittest import TestCase
from io import StringIO
from typing import List

class IoTDBRemovePartitionIT(TestCase):
    partition_interval = 100
    
    def setUp(self) -> None:
        logger = logging.getLogger('root')
        logger.setLevel(logging.TRACE)
        
        try:
            from iotdb import IOTDBConnection
            
            conn = IOTDBConnection("127.0.0.1", "6667")
            conn.connect()
            
            statement = conn.createStatement()
            
            for _ in range(10):
                # seq files
                for j in [1, 2]:
                    sql = f"INSERT INTO root.test{j}(timestamp, s0) VALUES ({_ * self.partition_interval + 50}, {_ * self.partition_interval + 50})"
                    statement.execute(sql)
                    
                if _ < 9:
                    statement.execute("FLUSH")
                
                # unseq files
                for j in [1, 2]:
                    sql = f"INSERT INTO root.test{j}(timestamp, s0) VALUES ({_ * self.partition_interval}, {_ * self.partition_interval})"
                    statement.execute(sql)
                    
                if _ < 9:
                    statement.execute("FLUSH")
                
            conn.commit()
        except Exception as e:
            logging.error(e)

    def tearDown(self) -> None:
        try:
            from iotdb import IOTDBConnection
            
            conn = IOTDBConnection("127.0.0.1", "6667")
            conn.connect()
            
            statement = conn.createStatement()
            
            for _ in range(10):
                # seq files
                for j in [1, 2]:
                    sql = f"INSERT INTO root.test{j}(timestamp, s0) VALUES ({_ * self.partition_interval + 50}, {_ * self.partition_interval + 50})"
                    statement.execute(sql)
                    
                if _ < 9:
                    statement.execute("FLUSH")
                
                # unseq files
                for j in [1, 2]:
                    sql = f"INSERT INTO root.test{j}(timestamp, s0) VALUES ({_ * self.partition_interval}, {_ * self.partition_interval})"
                    statement.execute(sql)
                    
                if _ < 9:
                    statement.execute("FLUSH")
                
            conn.commit()
        except Exception as e:
            logging.error(e)

    def test_remove_no_partition(self):
        try:
            from iotdb import IOTDBConnection
            
            conn = IOTDBConnection("127.0.0.1", "6667")
            conn.connect()
            
            statement = conn.createStatement()
            
            StorageEngine.getInstance().removePartitions(PartialPath("root.test1"), lambda storage_group_name, time_partition_id: False)
            
            result_set = statement.executeQuery("SELECT * FROM root.test1")
            count = 0
            while result_set.next():
                self.assertEqual(count // 2 * self.partition_interval + (count % 2) * 50, result_set.getLong(1))
                self.assertEqual(count // 2 * self.partition_interval + (count % 2) * 50, result_set.getLong(2))
                count += 1
            self.assertEqual(20, count)
        except Exception as e:
            logging.error(e)

    def test_remove_partial_partition(self):
        try:
            from iotdb import IOTDBConnection
            
            conn = IOTDBConnection("127.0.0.1", "6667")
            conn.connect()
            
            statement = conn.createStatement()
            
            StorageEngine.getInstance().removePartitions(PartialPath("root.test1"), lambda storage_group_name, time_partition_id: time_partition_id >= 5)
            StorageEngine.getInstance().removePartitions(PartialPath("root.test2"), lambda storage_group_name, time_partition_id: time_partition_id < 5)
            
            result_set = statement.executeQuery("SELECT * FROM root.test1")
            count = 0
            while result_set.next():
                self.assertEqual(count // 2 * self.partition_interval + (count % 2) * 50, result_set.getLong(1))
                self.assertEqual(count // 2 * self.partition_interval + (count % 2) * 50, result_set.getLong(2))
                count += 1
            self.assertEqual(10, count)
            
            result_set = statement.executeQuery("SELECT * FROM root.test2")
            while result_set.next():
                self.assertEqual(count // 2 * self.partition_interval + (count % 2) * 50 + 500, result_set.getLong(1))
                self.assertEqual(count // 2 * self.partition_interval + (count % 2) * 50 + 500, result_set.getLong(2))
                count += 1
            self.assertEqual(10, count)
        except Exception as e:
            logging.error(e)

    def test_remove_all_partition(self):
        try:
            from iotdb import IOTDBConnection
            
            conn = IOTDBConnection("127.0.0.1", "6667")
            conn.connect()
            
            statement = conn.createStatement()
            
            StorageEngine.getInstance().removePartitions(PartialPath("root.test1"), lambda storage_group_name, time_partition_id: True)
            
            result_set = statement.executeQuery("SELECT * FROM root.test1")
            self.assertFalse(result_set.next())
        except Exception as e:
            logging.error(e)

    def test_sql_remove_partition(self):
        try:
            from iotdb import IOTDBConnection
            
            conn = IOTDBConnection("127.0.0.1", "6667")
            conn.connect()
            
            statement = conn.createStatement()
            
            statement.execute("DELETE PARTITION root.test2 0,1,2,3,4")
            
            result_set = statement.executeQuery("SELECT * FROM root.test2")
            count = 0
            while result_set.next():
                self.assertEqual(count // 2 * self.partition_interval + (count % 2) * 50 + 500, result_set.getLong(1))
                self.assertEqual(count // 2 * self.partition_interval + (count % 2) * 50 + 500, result_set.getLong(2))
                count += 1
            self.assertEqual(10, count)
        except Exception as e:
            logging.error(e)

    def test_remove_one_partition_and_insert_data(self):
        try:
            from iotdb import IOTDBConnection
            
            conn = IOTDBConnection("127.0.0.1", "6667")
            conn.connect()
            
            statement = conn.createStatement()
            
            statement.execute("SET STORAGE GROUP TO root.test")
            statement.execute("INSERT INTO root.test.wf02.wt02(timestamp, status) VALUES (1, true)")
            statement.execute("SELECT * FROM root.test wf02 wt02")
            statement.execute("DELETE PARTITION root.test 0")
            statement.execute("SELECT * FROM root.test wf02 wt02")
            statement.execute("INSERT INTO root.test wf02 wt02(timestamp, status) VALUES (1, true)")
            
            result_set = statement.executeQuery("SELECT * FROM root.test wf02 wt02")
            self.assertTrue(result_set.next())
        except Exception as e:
            logging.error(e)

    def test_remove_partition_and_insert_unseq_data_and_merge(self):
        try:
            from iotdb import IOTDBConnection
            
            conn = IOTDBConnection("127.0.0.1", "6667")
            conn.connect()
            
            statement = conn.createStatement()
            
            statement.execute("SET STORAGE GROUP TO root.test")
            statement.execute("INSERT INTO root.test wf02 wt02(timestamp, status) VALUES (2, true)")
            statement.execute("SELECT * FROM root.test wf02 wt02")
            statement.execute("DELETE PARTITION root.test 0")
            statement.execute("SELECT * FROM root.test wf02 wt02")
            statement.execute("INSERT INTO root.test wf02 wt02(timestamp, status) VALUES (1, true)")
            
            result_set = statement.executeQuery("SELECT * FROM root.test wf02 wt02")
            self.assertTrue(result_set.next())
        except Exception as e:
            logging.error(e)

    def test_flush_and_remove_one_partition_and_insert_data(self):
        try:
            from iotdb import IOTDBConnection
            
            conn = IOTDBConnection("127.0.0.1", "6667")
            conn.connect()
            
            statement = conn.createStatement()
            
            statement.execute("SET STORAGE GROUP TO root.test")
            statement.execute("INSERT INTO root.test wf02 wt02(timestamp, status) VALUES (1, true)")
            statement.execute("FLUSH")
            statement.execute("DELETE PARTITION root.test 0")
            statement.execute("SELECT * FROM root.test wf02 wt02")
            statement.execute("INSERT INTO root.test wf02 wt02(timestamp, status) VALUES (1, true)")
            
            result_set = statement.executeQuery("SELECT * FROM root.test wf02 wt02")
            self.assertTrue(result_set.next())
        except Exception as e:
            logging.error(e)

    def test_insert_data(self):
        try:
            from iotdb import IOTDBConnection
            
            conn = IOTDBConnection("127.0.0.1", "6667")
            conn.connect()
            
            statement = conn.createStatement()
            
            for _ in range(10):
                # seq files
                for j in [1, 2]:
                    sql = f"INSERT INTO root.test{j}(timestamp, s0) VALUES ({_ * self.partition_interval + 50}, {_ * self.partition_interval + 50})"
                    statement.execute(sql)
                    
                if _ < 9:
                    statement.execute("FLUSH")
                
                # unseq files
                for j in [1, 2]:
                    sql = f"INSERT INTO root.test{j}(timestamp, s0) VALUES ({_ * self.partition_interval}, {_ * self.partition_interval})"
                    statement.execute(sql)
                    
                if _ < 9:
                    statement.execute("FLUSH")
                
            conn.commit()
        except Exception as e:
            logging.error(e)

if __name__ == "__main__":
    unittest.main()