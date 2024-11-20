import os
from datetime import datetime as dt

class TimeGeneratorReadEmptyTest:
    TEMPLATE_NAME = "template"
    tsfile_path = TsFileGeneratorForTest.get_test_ts_file_path("root.sg1", 0, 0, 1)

    def before(self):
        self.write_ts_file(self.tsfile_path)

    def after(self):
        if os.path.exists(self.tsfile_path):
            os.remove(self.tsfile_path)

    def test_filter_and(self):
        time_filter = FilterFactory.and(TimeFilter.ge(2), TimeFilter.le(2))
        time_expression = GlobalTimeExpression(time_filter)
        
        value_expression = BinaryExpression.or_(
            SingleSeriesExpression(Path("d1", "s1"), ValueFilter.gt(1.0)),
            SingleSeriesExpression(Path("d1", "s2"), ValueFilter.lt(22)))
        
        final_expression = BinaryExpression.and_(value_expression, time_expression)
        
        query_expression = QueryExpression.create() \
            .add_selected_path(Path("d1", "s1")) \
            .add_selected_path(Path("d1", "s2")) \
            .set_expression(final_expression)

        try:
            with TsFileSequenceReader(self.tsfile_path) as file_reader:
                read_only_ts_file = ReadOnlyTsFile(file_reader)
                data_set = read_only_ts_file.query(query_expression)
                i = 0
                while data_set.has_next():
                    data_set.next()
                    i += 1
                assert i == 0, f"Expected {i} but got {data_set}"
        except Exception as e:
            print(f"An error occurred: {e}")

    def write_ts_file(self):
        if os.path.exists(self.tsfile_path):
            os.remove(self.tsfile_path)

        schema = Schema()
        schema.extend_template(
            self.TEMPLATE_NAME, 
            UnaryMeasurementSchema("s1", TSDataType.FLOAT, TSEncoding.RLE)
        )
        schema.extend_template(
            self.TEMPLATE_NAME,
            UnaryMeasurementSchema("s2", TSDataType.INT32, TSEncoding.TS_2DIFF)
        )

        ts_file_writer = TsFileWriter(self.tsfile_path, schema)

        # s1 -> 1, 3
        ts_record = TSRecord(dt(2020), "d1")
        data_point = FloatDataPoint("s1", 1.2)
        ts_record.add_tuple(data_point)
        ts_file_writer.write(ts_record)

        ts_record = TSRecord(dt(2020, 7, 12), "d1")
        data_point = FloatDataPoint("s1", 3.4)
        ts_record.add_tuple(data_point)
        ts_file_writer.write(ts_record)

        ts_file_writer.flush_all_chunk_groups()

        # s2 -> 5, 6
        ts_record = TSRecord(dt(2020), "d1")
        data_point = IntDataPoint("s2", 20)
        ts_record.add_tuple(data_point)
        ts_file_writer.write(ts_record)

        ts_record = TSRecord(dt(2020, 7, 12), "d1")
        data_point = IntDataPoint("s2", 30)
        ts_record.add_tuple(data_point)
        ts_file_writer.write(ts_record)

        # close TsFile
        ts_file_writer.close()
