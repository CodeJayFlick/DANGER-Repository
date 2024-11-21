import csv
from datetime import datetime
from io import StringIO
from typing import List, Dict, Any

class ImportCsv:
    def __init__(self):
        self.target_path = None
        self.failed_file_directory = None

    @staticmethod
    def create_options() -> dict:
        options = {
            'file': {'required': True, 'arg_name': 'File or folder', 'has_arg': True},
            'failed_file': {'arg_name': 'Failed file directory', 'has_arg': True}
        }
        return options

    @staticmethod
    def parse_special_params(command_line: dict) -> None:
        time_zone_id = command_line.get('time-zone')
        target_path = command_line['file']
        failed_file_directory = command_line.get('failed-file')

    @staticmethod
    def import_from_target_path(host: str, port: int, username: str, password: str, target_path: str) -> None:
        try:
            session = Session(host, port, username, password)
            session.open()
            set_time_zone()

            if os.path.isfile(target_path):
                self.import_single_file(target_path)
            elif os.path.isdir(target_path):
                files = [f for f in os.listdir(target_path) if os.path.isfile(os.path.join(target_path, f))]
                for file in files:
                    self.import_single_file(os.path.join(target_path, file))
        except (IoTDBConnectionException, StatementExecutionException) as e:
            print(f"Encounter an error when connecting to server: {e}")

    @staticmethod
    def import_from_single_file(file_path: str) -> None:
        if not os.path.isfile(file_path):
            return

        try:
            with open(file_path, 'r') as file:
                reader = csv.reader(file)
                header_names = next(reader)

                device_and_measurement_names = {}
                header_type_map = {}
                header_name_map = {}

                for i, row in enumerate(reader):
                    if not row[0].startswith('#'):
                        break

                for j, column in enumerate(header_names):
                    if column == 'Time':
                        continue
                    elif column.startswith('Device.'):
                        device_and_measurement_names[column] = [measurement.strip() for measurement in header_names[j + 1:]]
                    else:
                        header_type_map[header_name_map.get(column)] = self.infer_data_type(row[j])

                failed_records = []

                if 'Time' not in header_names or 'Device' not in device_and_measurement_names:
                    return

                time_formatter = None
                for row in reader:
                    if row[0].startswith('#'):
                        continue

                    times = []
                    measurements_list = []
                    values_list = []
                    types_list = []

                    for j, column in enumerate(header_names):
                        if column == 'Time':
                            try:
                                timestamp = datetime.strptime(row[j], '%Y-%m-%d %H:%M:%S')
                                time_formatter = None
                            except ValueError as e:
                                print(f"Meet error when insert csv because the format of time is not supported: {e}")
                                return

                        elif column.startswith('Device.'):
                            measurement_name = row[header_names.index(column)]
                            values_list.append(self.infer_data_type(measurement_name))
                            measurements_list.append([measurement.strip() for measurement in header_names[j + 1:] if measurement.strip()])
                        else:
                            try:
                                value = self.infer_data_type(row[j])
                                times.append(timestamp)
                                types_list.append(values_list[-1])
                                values_list.append(value)
                            except ValueError as e:
                                print(f"Meet error when insert csv because the format of time is not supported: {e}")
                                return

                    if len(times) > 0 and len(measurements_list[0]) > 0:
                        try:
                            session.insert_records_of_one_device(device_and_measurement_names, times, measurements_list, types_list, values_list)
                        except (IoTDBConnectionException, StatementExecutionException):
                            print(f"Meet error when insert csv because: {e}")

                    if len(failed_records) > 0:
                        self.write_csv_file(header_names, failed_records)

                print("Import completely!")

        except Exception as e:
            print(f"Encounter an error while importing csv file: {e}")

    @staticmethod
    def read_csv_file(file_path: str) -> List[List[str]]:
        with open(file_path, 'r') as file:
            reader = csv.reader(file)
            return list(reader)

    @staticmethod
    def parse_headers(header_names: List[str], device_and_measurement_names: Dict[str, Any]) -> None:
        for header_name in header_names:
            if header_name == 'Time' or header_name == 'Device':
                continue

            try:
                value = self.infer_data_type(header_name)
                type_ = TYPE_MAP.get(value)

                if type_ is not None and device_and_measurement_names.get('device') is not None:
                    measurement_name = f"measurement.{header_name}"
                    device_and_measurement_names[measurement_name] = [value]

            except ValueError as e:
                print(f"Meet error when insert csv because the format of time is not supported: {e}")

    @staticmethod
    def query_type(device_names: str, header_type_map: Dict[str, Any], aligned_type: str) -> None:
        try:
            session = Session()
            session.execute_query_statement(f"SELECT * FROM {device_names} LIMIT 1")
        except (IoTDBConnectionException, StatementExecutionException):
            print("Meet error when insert csv because: ")

    @staticmethod
    def formatter_init(time: str) -> datetime:
        try:
            return datetime.strptime(time, '%Y-%m-%d %H:%M:%S')
        except ValueError as e:
            for time_format in TIME_FORMATS:
                try:
                    format = datetime.strptime(time, time_format)
                    print(f"Time format is {time_format}")
                    return format
                except ValueError as ignored:
                    pass

    @staticmethod
    def type_infer(value: str) -> Any:
        if value.startswith('"') and value.endswith('"'):
            return TEXT

        try:
            float_value = float(value)
            if math.isinf(float_value):
                return FLOAT
            elif -1e30 < float_value < 1e30:
                return DOUBLE
            else:
                return INT32
        except ValueError as e:
            pass

    @staticmethod
    def type_trans(value: str, type_: Any) -> Any:
        try:
            if type_ == TEXT:
                return value.strip('"')
            elif type_ == BOOLEAN:
                return Boolean.valueOf(value)
            else:
                return self.infer_data_type(value)

        except ValueError as e:
            print(f"Meet error when insert csv because the format of time is not supported: {e}")

    @staticmethod
    def write_csv_file(header_names: List[str], failed_records: List[List[Any]]) -> None:
        with StringIO() as file:
            writer = csv.writer(file)
            writer.writerow(header_names)

            for record in failed_records:
                writer.writerow(record)

            print("Failed records written to the CSV file.")

if __name__ == '__main__':
    import_csv = ImportCsv()
