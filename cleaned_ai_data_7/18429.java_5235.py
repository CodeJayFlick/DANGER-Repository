import os
import logging
from typing import List

class FileGenerator:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    output_data_file = None
    schema = None
    row_count = 1000
    max_number_of_points_in_page = 10
    inner_writer = None
    input_data_file = None
    error_output_data_file = None

    def generate_file(self, row_count: int, max_number_of_points_in_page: int) -> None:
        self.row_count = row_count
        old_max_number_of_points_in_page = config.get_max_number_of_points_in_page()
        config.set_max_number_of_points_in_page(max_number_of_points_in_page)

        self.prepare()
        self.write()
        config.set_max_number_of_points_in_page(old_max_number_of_points_in_page)

    def generate_file(self, row_count: int, max_number_of_points_in_page: int, file_path: str) -> None:
        self.row_count = row_count
        old_max_number_of_points_in_page = config.get_max_number_of_points_in_page()
        config.set_max_number_of_points_in_page(max_number_of_points_in_page)

        self.prepare()
        self.write(file_path)
        config.set_max_number_of_points_in_page(old_max_number_of_points_in_page)

    def generate_file(self, max_number_of_points_in_page: int) -> None:
        self.row_count = 1
        old_max_number_of_points_in_page = config.get_max_number_of_points_in_page()
        config.set_max_number_of_points_in_page(max_number_of_points_in_page)

        self.prepare(0, 0)
        self.write()
        config.set_max_number_of_points_in_page(old_max_number_of_points_in_page)

    def prepare(self) -> None:
        file = os.path.join(os.getcwd(), "input_data_file.txt")
        if not os.path.exists(file):
            with open(file, 'w') as f:
                pass
        self.input_data_file = file

        error_output_data_file = os.path.join(os.getcwd(), "error_output_data_file.txt")
        if not os.path.exists(error_output_data_file):
            with open(error_output_data_file, 'w') as f:
                pass
        self.error_output_data_file = error_output_data_file

    def prepare(self, device_num: int, measurement_num: int) -> None:
        file = os.path.join(os.getcwd(), "input_data_file.txt")
        if not os.path.exists(file):
            with open(file, 'w') as f:
                pass
        self.input_data_file = file

        error_output_data_file = os.path.join(os.getcwd(), "error_output_data_file.txt")
        if not os.path.exists(error_output_data_file):
            with open(error_output_data_file, 'w') as f:
                pass
        self.error_output_data_file = error_output_data_file

    def after(self) -> None:
        file = os.path.join(os.getcwd(), "input_data_file.txt")
        if os.path.exists(file):
            os.remove(file)

        file = os.path.join(os.getcwd(), self.output_data_file)
        if os.path.exists(file):
            os.remove(file)

        error_output_data_file = os.path.join(os.getcwd(), "error_output_data_file.txt")
        if os.path.exists(error_output_data_file):
            os.remove(error_output_data_file)

    def generate_sample_input_data_file(self) -> None:
        file = open("input_data_file.txt", 'w')
        start_time = 1480562618000
        for i in range(self.row_count):
            d1 = f"d1,{start_time+i},{i*10+1},s2,{i*10+2}"
            if i % 20 < 10:
                d1 += ",null"
            file.write(f"{d1}\n")

            d2 = f"d2,{start_time+i},{i*10+2},s3,{i*10+3}"
            if i % 20 < 5:
                d2 += ",null"
            file.write(f"{d2}\n")
        file.close()

    def generate_sample_input_data_file(self, device_num: int, measurement_num: int) -> None:
        file = open("input_data_file.txt", 'w')
        start_time = 1480562618000
        for i in range(device_num):
            for j in range(measurement_num):
                d = f"d{i},{start_time+i*measurement_num+j},{j+1}"
                file.write(f"{d}\n")
        file.close()

    def write(self) -> None:
        self.write("output_data_file.txt")

    def write(self, file_path: str) -> None:
        with open(file_path, 'w') as f:
            pass

    def generate_test_schema(self) -> None:
        schema = Schema()
        for i in range(7):
            path = Path(f"d1,s{i}")
            measurement_schema = UnaryMeasurementSchema(f"s{i}", TSDataType.INT32, TSEncoding.valueOf(config.get_value_encoder()))
            schema.register_timeseries(path, measurement_schema)

    def generate_test_schema(self, device_num: int) -> None:
        schema = Schema()
        for i in range(device_num):
            for j in range(7):
                path = Path(f"d{i},s{j}")
                measurement_schema = UnaryMeasurementSchema(f"s{j}", TSDataType.INT32, TSEncoding.valueOf(config.get_value_encoder()))
                schema.register_timeseries(path, measurement_schema)

    def write_to_ts_file(self) -> None:
        with open("input_data_file.txt", 'r') as f:
            in = f
            line_count = 0
            start_time = time.time()
            while True:
                if line_count % 1000000 == 0:
                    self.logger.info(f"write line:{line_count},use time:{(time.time() - start_time) / 1000}")
                str = in.readline().strip()
                record = RecordUtils.parse_simple_tuple_record(str, schema)
                inner_writer.write(record)
                line_count += 1
            end_time = time.time()
            self.logger.info(f"write line:{line_count},use time:{(end_time - start_time) / 1000}")
        in.close()

    def get_data_file(self, path: str) -> None:
        file = open(path, 'r')
        return file
