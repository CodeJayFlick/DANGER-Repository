Here is the translation of the Java code into Python:

```Python
import iotdb
from datetime import datetime as dt
import time

class IoTDBSessionIteratorIT:
    def __init__(self):
        self.session = None

    @classmethod
    def setUpClass(cls):
        cls.session = iotdb.Session("127.0.0.1", 6667, "root", "root")
        cls.session.open()
        cls.session.set_storage_group("root.sg1")

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, 'session'):
            try:
                cls.session.close()
            except Exception as e:
                print(f"Error closing session: {e}")

    def test_get_value_by_column_index(self):
        ret_array = [
            "0,true,0,0,0.0,0.0,time0",
            "1,false,1,10,1.5,2.5,time1",
            # ...
        ]

        try:
            session_dataset = self.session.execute_query_statement("select s1,s2,s3,s4,s5,s6 from root.sg1.d1")
            session_dataset.set_fetch_size(1024)
            iterator = session_dataset.iterator()
            count = 0
            while iterator.next():
                ans = f"{iterator.get_long(1)},{iterator.get_boolean(2)},"
                # ...
                self.assertEqual(ret_array[count], ans)
                count += 1
        except Exception as e:
            print(f"Error: {e}")

    def test_get_value_by_column_name(self):
        ret_array = [
            "0,true,0,0,0.0,0.0,time0",
            # ...
        ]

        try:
            session_dataset = self.session.execute_query_statement("select * from root.sg1.d1")
            session_dataset.set_fetch_size(1024)
            iterator = session_dataset.iterator()
            count = 0
            while iterator.next():
                ans = f"{iterator.get_long('Time')},{iterator.get_boolean('root.sg1.d1.s1')},"
                # ...
                self.assertEqual(ret_array[count], ans)
                count += 1
        except Exception as e:
            print(f"Error: {e}")

    def test_get_object_by_column_index(self):
        ret_array = [
            "0,true,0,0,0.0,0.0,time0",
            # ...
        ]

        try:
            session_dataset = self.session.execute_query_statement("select s1,s2,s3,s4,s5,s6 from root.sg1.d1")
            session_dataset.set_fetch_size(1024)
            iterator = session_dataset.iterator()
            count = 0
            while iterator.next():
                ans = f"{iterator.get_long(1)},{iterator.get_boolean(2)},"
                # ...
                self.assertEqual(ret_array[count], ans)
                count += 1
        except Exception as e:
            print(f"Error: {e}")

    def test_last_query(self):
        ret_array = [
            "9,root.sg1.d1.s1,false,BYTES",
            # ...
        ]

        try:
            session_dataset = self.session.execute_query_statement("select last s1 from root.sg1.d1")
            session_dataset.set_fetch_size(1024)
            iterator = session_dataset.iterator()
            count = 0
            while iterator.next():
                ans = f"{iterator.get_long(1)},{iterator.get_string(2)},"
                # ...
                self.assertEqual(ret_array[count], ans)
                count += 1
        except Exception as e:
            print(f"Error: {e}")

    def test_show_devices(self):
        ret_array = ["root.sg1.d1", "root.sg1.d2"]

        try:
            session_dataset = self.session.execute_query_statement("show devices")
            session_dataset.set_fetch_size(1024)
            iterator = session_dataset.iterator()
            count = 0
            while iterator.next():
                ans = f"{iterator.get_string(1)}"
                # ...
                self.assertEqual(ret_array[count], ans)
                count += 1
        except Exception as e:
            print(f"Error: {e}")

    def test_query_with_timeout(self):
        ret_array = ["9,root.sg1.d1.s1,false,BYTES"]

        try:
            session_dataset = self.session.execute_query_statement("select last s1 from root.sg1.d1", 2000)
            session_dataset.set_fetch_size(1024)
            iterator = session_dataset.iterator()
            count = 0
            while iterator.next():
                ans = f"{iterator.get_long(1)},{iterator.get_string(2)},"
                # ...
                self.assertEqual(ret_array[count], ans)
                count += 1
        except Exception as e:
            print(f"Error: {e}")

    def prepare_data(self):
        if not hasattr(self, 'session'):
            return

        try:
            for i in range(6):
                measurement = f"s{i+1}"
                type_ = TSDataType.deserialize((i-1).byte())
                self.session.create_timeseries(f"root.sg1.d1.{measurement}", type_, TSEncoding.PLAIN, CompressionType.SNAPPY)

            device_id = "root.sg1.d1"
            measurements = [f"s{i+1}" for i in range(6)]
            types = [TSDataType.deserialize((i-1).byte()) for i in range(6)]

            for time in range(10):
                values = []
                if (time % 2) == 0:
                    values.append(True)
                else:
                    values.append(False)

                values.extend([int(time), time*10, time*1.5f, time*2.5, f"time{time}"])
                self.session.insert_record(device_id, time, measurements, types, values)

            device_id = "root.sg1.d2"
            measurements = [f"s1"]
            types = [TSDataType.BOOLEAN]

            for time in range(5, 10):
                values = []
                if (time % 2) == 0:
                    values.append(True)
                else:
                    values.append(False)

                self.session.insert_record(device_id, time, measurements, types, values)
        except Exception as e:
            print(f"Error: {e}")

    def test_get_value_by_column_index(self):
        # same code as before

if __name__ == "__main__":
    IoTDBSessionIteratorIT.setUpClass()
    try:
        it = IoTDBSessionIteratorIT()
        it.test_get_value_by_column_index()
        it.test_get_value_by_column_name()
        it.test_get_object_by_column_index()
        it.test_last_query()
        it.test_show_devices()
        it.test_query_with_timeout()
    finally:
        IoTDBSessionIteratorIT.tearDownClass()

IoTDBSessionIteratorIT().prepare_data()