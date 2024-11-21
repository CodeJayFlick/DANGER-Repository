Here is the translation of the Java code into Python:

```Python
import os
from typing import List, Tuple

class FlinkTsFileBatchSink:
    DEFAULT_TEMPLATE = "template"

    @staticmethod
    def main(arg: str) -> None:
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
            {"type": int, "name": filed_names[0]},
            {"type": int, "name": filed_names[1]},
            {"type": int, "name": filed_names[2]},
            {"type": int, "name": filed_names[3]},
            {"type": int, "name": filed_names[4]},
            {"type": int, "name": filed_names[5]},
            {"type": int, "name": filed_names[6]}
        ]
        
        schema = {}
        for field_name in filed_names:
            if field_name != QueryConstant.RESERVED_TIME:
                schema[field_name] = {
                    "data_type": TSDataType.INT64,
                    "encoding": TSEncoding.TS_2DIFF
                }
        
        converter = RowTSRecordConverter(type_informations)
        output_format = TSRecordOutputFormat(schema, converter)

        data: List[Tuple[int]] = []
        for i in range(7):
            row_data = [i+1] * 7
            data.append(tuple(row_data))
        
        paths = [(field_name, True) for field_name in filed_names if field_name != QueryConstant.RESERVED_TIME]
        
        with open(path, 'w') as f:
            output_format.open(f)
            for row in data:
                converter.convert_to_ts_record(row).write(output_format)

        result: List[str] = TsFileUtils.readTsFile(path, paths)
        for row in result:
            print(row)


if __name__ == "__main__":
    FlinkTsFileBatchSink.main("")
```

Please note that this is a Python translation of the Java code. It may not be exactly equivalent to the original Java code due to differences between languages and their respective libraries.