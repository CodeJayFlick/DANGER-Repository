import os
from datetime import datetime as dt

class TsFileRewriteToolTest:
    def __init__(self):
        self.new_enable_partition = True
        self.new_partition_interval = 3600 * 1000
        self.max_timestamp = 10 ** 10
        self.folder = "target" + os.sep + "split"
        self.storage_group = "root.sg_0"
        self.device1 = f"{self.storage_group}.device_1"
        self.device2 = f"{self.storage_group}.device_2"
        self.sensor1 = "sensor_1"
        self.sensor2 = "sensor_2"
        self.value_offset = 1

    def setUp(self):
        os.makedirs(self.folder, exist_ok=True)
        path = f"{os.sep}{dt.now().strftime('%Y%m%d%H%M%S')}--0.tsfile"
        self.path = os.path.join(self.folder, path)

    @classmethod
    def tearDown(cls):
        try:
            os.remove(cls.path)
        except FileNotFoundError:
            pass

    def split_one_ts_file_with_two_devices_and_sensors_test(self):
        device_sensors_map = {"device_1": ["sensor_1"], "device_2": ["sensor_2"]}
        self.create_one_ts_file(device_sensors_map)
        self.split_file_and_query_check(device_sensors_map)

    # ... rest of the methods

if __name__ == "__main__":
    test = TsFileRewriteToolTest()
    test.setUp()
