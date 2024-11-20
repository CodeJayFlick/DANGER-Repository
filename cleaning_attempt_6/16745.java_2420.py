import os
from hadoop import HadoopFileSystem
from hadoop.mapreduce import JobConf, Tool
from hadoop.io import Text, DoubleWritable
from hadoop.input.api import TextInputFormat
from hadoop.output.api import TextOutputFormat

class TSFMRReadExample:
    def __init__(self):
        pass

    @classmethod
    def main(cls, args):
        if len(args) != 3:
            print("Please give hdfs url, input path, output path")
            return

        configuration = HadoopFileSystem.get_config()
        job_conf = JobConf(configuration)

        fs = HadoopFileSystem.get(configuration)
        if os.path.exists(args[2]):
            fs.delete(args[2], True)

        job_conf.set_job_name("TsFile read jar")
        job_conf.set_mapper_class(TSMapper)
        job_conf.set_reducer_class TSReducer
        job_conf.set_input_format(TextInputFormat.class)
        job_conf.set_output_format(TextOutputFormat.class)
        job_conf.set_map_output_key(Text)
        job_conf.set_map_output_value(DoubleWritable)
        job_conf.set_reduce_output_key(Text)
        job_conf.set_reduce_output_value(DoubleWritable)

        TextInputFormat.add_input_path(job_conf, args[1])
        TextOutputFormat.setOutput_path(job_conf, args[2])

        try:
            Tool.run_and_exit(job_conf)
        except Exception as e:
            print(str(e))

class TSMapper:
    def map(self, key, value, context):
        delta_object_id = str(value.get("device_1. sensor_3"))
        context.write(Text(delta_object_id), DoubleWritable(0))
        for k in value.keys():
            if "sensor_3" == str(k):
                double_value = float(str(value[k]))
                context.write(Text(delta_object_id), DoubleWritable(double_value))

class TSReducer:
    def reduce(self, key, values, context):
        sum = 0
        for value in values:
            sum += float(str(value))
        context.write(key, DoubleWritable(sum))


if __name__ == "__main__":
    TSFMRReadExample.main(sys.argv[1:])
