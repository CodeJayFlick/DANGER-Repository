Here is the translation of the Java code to Python:

```Python
import os
from io import StringIO
import csv
import random

class IoTDBWatermarkTest:
    def __init__(self):
        self.filePath1 = "watermarked_query_result.csv"
        self.filePath2 = "notWatermarked_query_result.csv"

    @classmethod
    def setUpClass(cls):
        cls.insert_data()

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(self.filePath1):
            os.remove(self.filePath1)
        if os.path.exists(self.filePath2):
            os.remove(self.filePath2)

    @staticmethod
    def insert_data():
        with open('iotdb.csv', 'w') as f:
            writer = csv.writer(f)
            for time in range(1000):
                row = [time, random.randint(1, 50), random.randint(1, 50)]
                if time % 10 == 0:
                    row.append(random.randint(1, 50))
                else:
                    row.extend([random.randint(1, 50) for _ in range(2)])
                writer.writerow(row)

    def encode_and_decode_test1(self):
        with open('iotdb.csv', 'r') as f:
            reader = csv.reader(f)
            next(reader)  # skip header
            for row in reader:
                print(','.join(row))

        alpha = 0.1
        is_watermarked = WatermarkDetector.is_watermarked(
            self.filePath1, "ASDFGHJKL", "10101000100", 5, 5, alpha, 1, 'int')
        assert is_watermarked

    def encode_and_decode_test2(self):
        with open('iotdb.csv', 'r') as f:
            reader = csv.reader(f)
            next(reader)  # skip header
            for row in reader:
                print(','.join(row))

        alpha = 0.1
        is_watermarked = WatermarkDetector.is_watermarked(
            self.filePath2, "ASDFGHJKL", "10101000100", 5, 5, alpha, 1, 'int')
        assert not is_watermarked

if __name__ == '__main__':
    IoTDBWatermarkTest().encode_and_decode_test1()
    IoTDBWatermarkTest().encode_and_decode_test2()

class WatermarkDetector:
    @staticmethod
    def is_watermarked(file_path, secret_key, watermark_bit_string, embed_row_cycle, embed_lsb_num, alpha, column_index, data_type):
        # implement your logic here to detect watermarks
        pass

# Usage: 
IoTDBWatermarkTest().setUpClass()
IoTDBWatermarkTest().encode_and_decode_test1()
IoTDBWatermarkTest().encode_and_decode_test2()
IoTDBWatermarkTest().tearDownClass()

```

Note that the `WatermarkDetector` class is just a placeholder and you need to implement your watermark detection logic there.