Here is the translation of the Java code to Python:

```Python
import os
from datetime import datetime as dt
from typing import Dict, List

class TSMRWriteExample:
    def __init__(self):
        pass

    @staticmethod
    def main(args: List[str]) -> None:
        if len(args) != 3:
            print("Please give hdfs url, input path, output path")
            return

        schema = Schema()
        sensor_num = 3

        for i in range(2):
            schema.register_timeseries(
                org.apache.iotdb.tsfile.read.common.Path(Constant.DEVICE_1, Constant.SENSOR_PREFIX + (i+1)),
                UnaryMeasurementSchema(Constant.SENSOR_PREFIX + (i+1), TSDataType.INT64, TSEncoding.TS_2DIFF)
            )

        for i in range(2, sensor_num):
            schema.register_timeseries(
                org.apache.iotdb.tsfile.read.common.Path(Constant.DEVICE_1, Constant.SENSOR_PREFIX + (i+1)),
                UnaryMeasurementSchema(Constant.SENSOR_PREFIX + (i+1), TSDataType.DOUBLE, TSEncoding.TS_2DIFF)
            )

        TSFOutputFormat.set_schema(schema)

        input_path = Path(args[1])
        output_path = Path(args[2])

        configuration = Configuration()
        # set file system configuration
        # configuration.set("fs.defaultFS", HDFSURL)
        job = Job.getInstance(configuration)

        fs = FileSystem.get(configuration)
        if fs.exists(output_path):
            fs.delete(output_path, True)

        job.set_job_name("TsFile write jar")
        job.set_jar_by_class(TSMRWriteExample.__class__)
        # set mapper and reducer
        job.set_mapper_class(TSMapper().__class__)
        job.set_reducer_class(TSReducer().__class__)

        # set mapper output key and value
        job.set_map_output_key_class(Text().__class__)
        job.set_map_output_value_class(MapWritable().__class__)
        # set reducer output key and value
        job.set_output_key_class(NullWritable().__class__)
        job.set_output_value_class(HDFSTSRecord().__class__)

        # set input format and output format
        job.set_input_format_class(TSFInputFormat().__class__)
        job.set_output_format_class(TSFOutputFormat().__class__)

        # set input file path
        TSFInputFormat().set_input_paths(job, [input_path])
        # set output file path
        TSFOutputFormat().set_output_path(job, [output_path])

        try:
            if job.wait_for_completion(True):
                print("Execute successfully")
            else:
                print("Execute unsuccessfully")
        except InterruptedException as e:
            Thread.currentThread().interrupt()
            raise IOException(e.get_message())

class TSMapper(Mapper[NullWritable, MapWritable, Text, MapWritable]):
    def map(self, key: NullWritable, value: MapWritable, context: Mapper.Context) -> None:
        delta_object_id = text(value.get(text("device_1")))
        timestamp = long((long_writable(value.get(text("time_stamp")))).get())
        if timestamp % 100000 == 0:
            context.write(delta_object_id, value)

class TSReducer(Reducer[Text, MapWritable, NullWritable, HDFSTSRecord]):
    def reduce(self, key: Text, values: Iterable[MapWritable], context: Reducer.Context) -> None:
        sensor1_value_sum = long(0)
        sensor2_value_sum = long(0)
        sensor3_value_sum = float(0)
        num = 0
        for value in values:
            num += 1
            sensor1_value_sum += (long((long_writable(value.get(text("sensor_1")))).get()))
            sensor2_value_sum += (long((long_writable(value.get(text("sensor_2")))).get()))
            sensor3_value_sum += (float((double_writable(value.get(text("sensor_3")))).get()))

        ts_record = HDFSTSRecord(1, key)
        if num != 0:
            data_point1 = LongDataPoint(Constant.SENSOR_1, sensor1_value_sum / num)
            data_point2 = LongDataPoint(Constant.SENSOR_2, sensor2_value_sum / num)
            data_point3 = DoubleDataPoint(Constant.SENSOR_3, sensor3_value_sum / num)
            ts_record.add_tuple(data_point1)
            ts_record.add_tuple(data_point2)
            ts_record.add_tuple(data_point3)

        context.write(NullWritable(), ts_record)