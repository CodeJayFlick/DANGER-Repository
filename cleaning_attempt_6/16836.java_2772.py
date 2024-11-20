import os
from typing import List

class TsFileTestHelper:
    logger = None

    @staticmethod
    def delete_ts_file(file_path: str) -> bool:
        file = os.path.join(os.getcwd(), file_path)
        return os.remove(file)

    @staticmethod
    def write_ts_file(file_path: str):
        try:
            if os.path.exists(file_path):
                os.remove(file_path)

            schema = {}
            sensor_num = 10

            for i in range(sensor_num):
                measurement_schema = {"name": f"sensor_{i+1}", "data_type": "INT64", "encoding": "TS_2DIFF"}
                schema[f"device_1/sensor_{i+1}"] = measurement_schema
        except Exception as e:
            print(f"Error: {e}")

    @staticmethod
    def main(args):
        file_path = "example_mr.tsfile"
        if os.path.exists(file_path):
            TsFileTestHelper.delete_ts_file(file_path)
        TsFileTestHelper.write_ts_file(file_path)

if __name__ == "__main__":
    try:
        TsFileTestHelper.main([])
    except Exception as e:
        print(f"Error: {e}")
