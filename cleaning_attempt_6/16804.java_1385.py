import os
from typing import List, Tuple

class RowTsFileConnectorTestBase:
    def __init__(self):
        self.tmp_dir = None
        self.config = {}
        self.filed_names = [
            "reserved_time",
            "device_1.sensor_1", 
            "device_1.sensor_2", 
            "device_1.sensor_3", 
            "device_2.sensor_1", 
            "device_2.sensor_2", 
            "device_2.sensor_3"
        ]
        self.type_informations = [
            ("LONG", int),
            ("FLOAT", float), 
            ("INT", int), 
            ("INT", int), 
            ("FLOAT", float), 
            ("INT", int), 
            ("INT", int)
        ]

    def prepare_temp_directory(self):
        if not self.tmp_dir:
            self.tmp_dir = os.path.join(TsFileWriteUtil.TMP_DIR, str(uuid.uuid4()))
            os.makedirs(self.tmp_dir)
            self.config["batch_size"] = 500

    def clean_temp_directory(self):
        tmp_dir_file = os.path.join(self.tmp_dir)
        try:
            import shutil
            shutil.rmtree(tmp_dir_file)
        except FileNotFoundError:
            pass

# Usage example:

test_base = RowTsFileConnectorTestBase()
test_base.prepare_temp_directory()

try:
    # Your test code here...
finally:
    test_base.clean_temp_directory()
