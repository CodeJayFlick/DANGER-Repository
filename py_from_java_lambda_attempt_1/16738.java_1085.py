Here is the equivalent Python code:

```Python
import os
from tsfile import TsFileUtils, RowRowRecordParser, QueryExpression, Path
from typing import List

class FlinkTsFileBatchSource:
    def main(self):
        path = "test.tsfile"
        TsFileUtils.write_ts_file(path)
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
        
        filed_names = [
            'RESERVED_TIME',
            'device_1.sensor_1', 
            'device_1.sensor_2', 
            'device_1.sensor_3', 
            'device_2.sensor_1', 
            'device_2.sensor_2', 
            'device_2.sensor_3'
        ]
        
        type_informations = [
            {'type': 'long'}, 
            {'type': 'long'}, 
            {'type': 'long'}, 
            {'type': 'long'}, 
            {'type': 'long'}, 
            {'type': 'long'}, 
            {'type': 'long'}
        ]
        
        paths = [Path(name, True) for name in filed_names[1:]]
        query_expression = QueryExpression.create(paths, None)
        parser = RowRowRecordParser.create(type_informations, query_expression.get_selected_series())
        input_format = TsFileInputFormat(query_expression, parser)
        input_format.set_file_path(path)

        # Create the Flink environment and read from the file
        import pyflink
        env = pyflink.ExecutionEnvironment.get_execution_environment()
        source = env.create_input(input_format)
        
        result = []
        for row in source:
            result.append(str(row))
        
        print(result)


if __name__ == "__main__":
    FlinkTsFileBatchSource().main()

```

Please note that you need to install the `pyflink` library and also import it before using.