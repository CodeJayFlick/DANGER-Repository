import unittest
from io import IOException
from typing import Any

class TSFHiveInputFormatTest(unittest.TestCase):

    def setUp(self):
        self.input_split = None
        self.input_format = None
        self.job = None
        self.file_path = TestConstant.BASE_OUTPUT_PATH + "test.tsfile"
        TsFileTestHelper.write_ts_file(self.file_path)
        self.input_format = TSFHiveInputFormat()
        job_path = self.file_path.replace('\\', '/')
        self.job = JobConf(job_path, '127.0.0.1')
        path = Path(self.file_path)
        hosts = ['127.0.0.1']
        self.input_split = TSFInputSplit(path, hosts, 0, 3727688)

    def tearDown(self):
        TsFileTestHelper.delete_ts_file(self.file_path)

    @unittest.skipIf(sys.version_info < (3,7), "Python version is too low")
    def test_get_record_reader(self):
        try:
            record_reader = self.input_format.get_record_reader(self.input_split, self.job)
            self.assertIsInstance(record_reader, TSFHiveRecordReader)
        except IOException as e:
            print(e.stacktrace())
            self.fail()

    @unittest.skipIf(sys.version_info < (3,7), "Python version is too low")
    def test_get_splits(self):
        try:
            input_splits = self.input_format.get_splits(self.job, 0)
            self.assertEqual(1, len(input_splits))
            self.assertIsInstance(input_splits[0], TSFInputSplit)
            input_split = input_splits[0]
        except IOException as e:
            print(e.stacktrace())
            self.fail()

if __name__ == '__main__':
    unittest.main()
