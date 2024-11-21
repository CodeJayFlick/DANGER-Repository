import os
from datetime import datetime

class TsFileGeneratorForTest:
    START_TIMESTAMP = 1480562618000
    
    def __init__(self):
        self.input_data_file = None
        self.output_data_file = get_test_ts_file_path("root.sg1", 0, 0, 0)
        self.error_output_data_file = None

    @staticmethod
    def generate_file(min_row_count, max_row_count, chunk_group_size, page_size):
        TsFileGeneratorForTest.row_count = max_row_count
        TsFileGeneratorFSFactory.get_fs_factory().get_file(self.output_data_file).parent.mkdir(parents=True)
        self.input_data_file = get_test_ts_file_path("root.sg1", 0, 0, 1)
        TsFileGeneratorFSFactory.get_fs_factory().get_file(self.input_data_file).parent.mkdir(parents=True)
        self.error_output_data_file = get_test_ts_file_path("root.sg1", 0, 0, 2)
        TsFileGeneratorFSFactory.get_fs_factory().get_file(self.error_output_data_file).parent.mkdir(parents=True)

    @staticmethod
    def after():
        if os.path.exists(TsFileGeneratorForTest.input_data_file):
            os.remove(TsFileGeneratorForTest.input_data_file)
        if os.path.exists(TsFileGeneratorForTest.output_data_file):
            os.remove(TsFileGeneratorForTest.output_data_file)
        if os.path.exists(TsFileGeneratorForTest.error_output_data_file):
            os.remove(TsFileGeneratorForTest.error_output_data_file)

    @staticmethod
    def generate_sample_input_data_file(min_row_count, max_row_count):
        with open(self.input_data_file, 'w') as fw:
            start_time = TsFileGeneratorForTest.START_TIMESTAMP
            for i in range(max_row_count):
                # write d1
                str_d1 = f"d1,{start_time + i},{i * 10 + 1},s2,{i * 10 + 2}"
                if i % 5 == 0:
                    str_d1 += ",s3," + (i * 10 + 3)
                if i % 8 == 0:
                    str_d1 += ",s4,dog" + i
                if i % 9 == 0:
                    str_d1 += ",s5,false"
                fw.write(str_d1 + "\r\n")

                # write d2
                str_d2 = f"d2,{start_time + i},s2,{i * 10 + 2},s3," + (i * 10 + 3)
                if i % 20 < 5:
                    str_d2 += ",s1," + (i * 10 + 1)
                if i % 8 == 0:
                    str_d2 += ",s4,dog" + i
                fw.write(str_d2 + "\r\n")

            # write error
            d = f"d2,3,{start_time + TsFileGeneratorForTest.row_count},{TsFileGeneratorForTest.row_count * 10 + 2},s-1," + (TsFileGeneratorForTest.row_count * 10 + 2)
            fw.write(d + "\r\n")
            d = f"d2,{start_time + TsFileGeneratorForTest.row_count + 1},2,s-1," + (TsFileGeneratorForTest.row_count * 10 + 2)
            fw.write(d + "\r\n")

        fw.close()

    @staticmethod
    def write():
        with open(TsFileGeneratorForTest.output_data_file, 'w') as inner_writer:
            schema = generate_test_schema()
            TSFileDescriptor.getInstance().getConfig().set_group_size_in_byte(chunk_group_size)
            TSFileDescriptor.getInstance().getConfig().setMax_number_of_points_in_page(page_size)

            try:
                scanner = Scanner(TsFileGeneratorForTest.input_data_file)
                while scanner.has_next_line():
                    str = scanner.next_line()
                    record = RecordUtils.parse_simple_tuple_record(str, schema)
                    inner_writer.write(record)
            except WriteProcessException as e:
                print(e.stacktrace())

    @staticmethod
    def generate_test_schema():
        schema = Schema()
        schema.register_timeseries(Path("d1", "s1"), UnaryMeasurementSchema("s1", TSDataType.INT32, TSEncoding.RLE))
        schema.register_timeseries(Path("d2", "s1"), UnaryMeasurementSchema("s1", TSDataType.INT32, TSEncoding.RLE))

    @staticmethod
    def get_test_ts_file_path(logical_storage_group_name, virtual_storage_group_id, time_partition_id, ts_file_version):
        file_path = f"{TestConstant.TEST_TSFILE_PATH}{logical_storage_group_name},{virtual_storage_group_id},{time_partition_id}"
        file_name = str(datetime.now()) + FilePathUtils.FILE_NAME_SEPARATOR + ts_file_version + "-0-0.tsfile"
        return os.path.join(file_path, file_name)

class Scanner:
    def __init__(self, file):
        self.file = file

    def has_next_line(self):
        with open(self.file) as f:
            for line in f:
                if not line.strip():
                    continue
                yield line.strip()

    def next_line(self):
        return next(iter(Scanner(self.file)))

class FilePathUtils:
    FILE_NAME_SEPARATOR = "_"

TestConstant.TEST_TSFILE_PATH = "path_to_your_test_tsfile_path"
