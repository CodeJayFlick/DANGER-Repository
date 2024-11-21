import os
from typing import List

class FlinkTsFileStreamSource:
    def __init__(self):
        pass

    @staticmethod
    def main():
        path = "test.tsfile"
        # TsFileUtils.writeTsFile(path)
        try:
            with open(path, 'w') as f:
                pass  # implement your logic here to write the ts file
        finally:
            if os.path.exists(path):
                os.remove(path)

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
            'long',  # Types.LONG
            'long',
            'long',
            'long',
            'long',
            'long',
            'long'
        ]

        paths: List[str] = [f"{s}.tsfile" for s in filed_names[1:]]

        row_type_info = RowTypeInfo(type_informations, filed_names)
        query_expression = QueryExpression.create(paths, None)  # implement your logic here to create the query expression
        parser = RowRowRecordParser.create(row_type_info, query_expression.get_selected_series())  # implement your logic here to create the record parser

        input_format = TsFileInputFormat(query_expression, parser)
        senv = StreamExecutionEnvironment.get_execution_environment()
        input_format.set_file_path("source.tsfile")
        source: DataStream[Row] = senv.create_input(input_format)

        row_string_stream: DataStream[str] = source.map(lambda x: str(x))
        result_iterator = row_string_stream.collect()

        for line in result_iterator:
            print(line)


if __name__ == "__main__":
    FlinkTsFileStreamSource.main()
