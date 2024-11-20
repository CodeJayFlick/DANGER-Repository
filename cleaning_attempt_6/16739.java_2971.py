import os
from typing import List, Tuple

class FlinkTsFileStreamSink:
    DEFAULT_TEMPLATE = "template"

    @staticmethod
    def main():
        path = "test.tsfile"
        if not os.path.exists(path):
            open(path, 'w').close()
        
        filed_names = [
            QueryConstant.RESERVED_TIME,
            "device_1.sensor_1",
            "device_1.sensor_2",
            "device_1.sensor_3",
            "device_2.sensor_1",
            "device_2.sensor_2",
            "device_2.sensor_3"
        ]

        type_informations = [
            {"type": int, "name": QueryConstant.RESERVED_TIME},
            {"type": int, "name": "device_1.sensor_1"},
            {"type": int, "name": "device_1.sensor_2"},
            {"type": int, "name": "device_1.sensor_3"},
            {"type": int, "name": "device_2.sensor_1"},
            {"type": int, "name": "device_2.sensor_2"},
            {"type": int, "name": "device_2.sensor_3"}
        ]

        schema = {}
        for field_name in filed_names:
            if field_name == QueryConstant.RESERVED_TIME:
                continue
            schema[field_name] = {
                "data_type": TSDataType.INT64,
                "encoding": TSEncoding.TS_2DIFF
            }

        converter = RowTSRecordConverter(type_informations)
        output_format = TSRecordOutputFormat(schema, converter)
        output_format.output_file_path = path

        data: List[Tuple] = []
        for i in range(7):
            row_data = [i+1, 2*(i+1), 3*(i+1), 4*(i+1), 5*(i+1), 6*(i+1), 7*(i+1)]
            data.append(tuple(row_data))

        stream_execution_environment = StreamExecutionEnvironment.get_execution_environment()
        source_stream = stream_execution_environment.from_collection(data, type_informations)
        result_stream = (
            source_stream
                .map(lambda t: Row(*[t[i] for i in range(7)]))
                .returns(type_informations)
                .write_to(output_format)
        )

        result_stream.execute()

        paths = [Path(s) for s in filed_names if s != QueryConstant.RESERVED_TIME]
        result = TsFileUtils.read_ts_file(path, paths)

        for row in result:
            print(row)


if __name__ == "__main__":
    FlinkTsFileStreamSink.main()
