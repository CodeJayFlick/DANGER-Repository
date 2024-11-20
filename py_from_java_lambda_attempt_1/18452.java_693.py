Here is the translation of the Java code into Python:

```Python
import os
from typing import List

class ForceAppendTsFileWriterTest:
    FILE_NAME = TsFileGeneratorForTest.get_test_ts_file_path("root.sg1", 0, 0, 1)
    fs_factory = FSFactoryProducer().get_fs_factory()

    def test(self):
        file = self.fs_factory.get_file(self.FILE_NAME)

        if os.path.exists(file.name):
            raise Exception(f"Do not know why the file exists.... {file.name}")

        print(file.name)
        parent_dir = os.path.dirname(file.name)
        if not os.path.exists(parent_dir):
            try:
                os.makedirs(parent_dir, exist_ok=True)
            except OSError as e:
                raise Exception(f"folder is not a directory.... {parent_dir}, error: {e}")
        
        writer = TsFileWriter(file)

        writer.register_timeseries(Path("d1", "s1"), UnaryMeasurementSchema("s1", TSDataType.FLOAT, TSEncoding.RLE))
        writer.register_timeseries(Path("d1", "s2"), UnaryMeasurementSchema("s2", TSDataType.FLOAT, TSEncoding.RLE))

        writer.write(TSRecord(1, "d1").add_tuple(FloatDataPoint("s1", 5)).add_tuple(FloatDataPoint("s2", 4)))
        writer.write(TSRecord(2, "d1").add_tuple(FloatDataPoint("s1", 5)).add_tuple(FloatDataPoint("s2", 4)))

        writer.flush_all_chunk_groups()

        first_metadata_position = writer.get_iowriter().get_pos()
        writer.close()

        fwriter = ForceAppendTsFileWriter(file)
        self.assertEqual(first_metadata_position, fwriter.truncate_position)

        fwriter.do_truncate()

        # write more data into this TsFile
        writer = TsFileWriter(fwriter)
        writer.register_timeseries(Path("d1", "s1"), UnaryMeasurementSchema("s1", TSDataType.FLOAT, TSEncoding.RLE))
        writer.register_timeseries(Path("d1", "s2"), UnaryMeasurementSchema("s2", TSDataType.FLOAT, TSEncoding.RLE))

        writer.write(TSRecord(3, "d1").add_tuple(FloatDataPoint("s1", 5)).add_tuple(FloatDataPoint("s2", 4)))
        writer.close()

        read_only_ts_file = ReadOnlyTsFile(TsFileSequenceReader(file.name))
        
        path_list: List[Path] = [Path("d1", "s1"), Path("d1", "s2")]
        query_expression = QueryExpression.create(path_list, None)
        data_set = read_only_ts_file.query(query_expression)

        record = next(data_set)
        self.assertEqual(1, record.timestamp)
        self.assertAlmostEqual(5.0, record.fields[0].get_float_v(), 0.001)
        self.assertAlmostEqual(4.0, record.fields[1].get_float_v(), 0.001)

        record = next(data_set)
        self.assertEqual(2, record.timestamp)
        self.assertAlmostEqual(5.0, record.fields[0].get_float_v(), 0.001)
        self.assertAlmostEqual(4.0, record.fields[1].get_float_v(), 0.001)

        record = next(data_set)
        self.assertEqual(3, record.timestamp)
        self.assertAlmostEqual(5.0, record.fields[0].get_float_v(), 0.001)
        self.assertAlmostEqual(4.0, record.fields[1].get_float_v(), 0.001)

        read_only_ts_file.close()
        self.assertFalse(data_set.has_next())

        os.remove(file.name)


if __name__ == "__main__":
    test = ForceAppendTsFileWriterTest()
    try:
        test.test()
    except Exception as e:
        print(f"Error: {e}")
```

Please note that this is a direct translation of the Java code into Python, and it may not be perfect. You might need to adjust some parts according to your specific requirements or environment.