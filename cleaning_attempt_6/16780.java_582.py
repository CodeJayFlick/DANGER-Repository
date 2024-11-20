import os
from datetime import datetime

class TSFileWriter:
    def __init__(self, file_path):
        self.file_path = file_path

    def write(self, tablet):
        # implement writing logic here


class Tablet:
    def __init__(self, device, measurement_schemas):
        self.device = device
        self.measurement_schemas = measurement_schemas
        self.timestamps = []
        self.values = []

    def add_value(self, value_name, row_number, value):
        for schema in self.measurement_schemas:
            if isinstance(schema, VectorMeasurementSchema) and value_name in schema.get_sub_measurements_list():
                # implement adding logic here


class VectorMeasurementSchema:
    def __init__(self, vector_name, measurement_names, data_types):
        self.vector_name = vector_name
        self.measurement_names = measurement_names
        self.data_types = data_types

    def get_sub_measurements_list(self):
        return self.measurement_names


def main():
    try:
        path = "test.tsfile"
        file_path = os.path.join(os.getcwd(), path)
        if os.path.exists(file_path) and not os.remove(file_path):
            raise Exception("can not delete " + file_path)

        ts_file_descriptor_config = TSFileDescriptor()
        ts_file_descriptor_config.max_degree_of_index_node = 3

        schema = Schema()

        device_name = f"device_{1}"
        sensor_prefix = "sensor_"
        vector_name = "vector1"

        row_num = 10000
        multi_sensor_num = 10

        measurement_names = [f"{sensor_prefix}{i+1}" for i in range(multi_sensor_num)]
        data_types = [TSDataType.INT64] * multi_sensor_num

        measurement_schemas = []

        for i in range(multi_sensor_num):
            vector_measurement_schema = VectorMeasurementSchema(vector_name, measurement_names[i:i + 1], [data_types[i]])
            measurement_schemas.append(vector_measurement_schema)

        schema.register_timeseries(Path(device_name, vector_name), measurement_schemas[0])

        ts_file_writer = TSFileWriter(file_path)
        tablet = Tablet(device_name, measurement_schemas)

        for r in range(row_num):
            timestamp = datetime.now().timestamp()
            value = 1000000

            row_size = len(tablet.timestamps) + 1
            tablet.timestamps.append(timestamp)
            tablet.values.append(value)

        ts_file_writer.write(tablet)

    except Exception as e:
        print(f"meet error in TsFileWrite with tablet: {e}")


if __name__ == "__main__":
    main()
