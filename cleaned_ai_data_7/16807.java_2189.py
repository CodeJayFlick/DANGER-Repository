import os
from unittest import TestCase


class RowTsFileInputFormatTestBase(TestCase):
    def setUp(self) -> None:
        self.source_ts_file_path1 = os.path.join(temp_dir, "source1.tsfile")
        self.source_ts_file_path2 = os.path.join(temp_dir, "source2.tsfile")

        TsFileWriteUtil.create_1(self.source_ts_file_path1)
        TsFileWriteUtil.create_2(self.source_ts_file_path2)

    def prepare_input_format(self, file_path: str) -> None:
        return TsFileInputFormat(file_path, query_expression, parser, config)


# You need to define these functions elsewhere in your code
def create_1(file_path):
    # Your implementation here

def create_2(file_path):
    # Your implementation here


class RowTsFileConnectorTestBase(TestCase):
    pass
