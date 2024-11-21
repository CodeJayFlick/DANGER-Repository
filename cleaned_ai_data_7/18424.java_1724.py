import os
from unittest import TestCase


class TsFileRestorableReaderTest(TestCase):

    FILE_PATH = 'outputDataFile'

    def setUp(self):
        self.fs_factory = FSFactoryProducer().get_fs_factory()

    @classmethod
    def tearDownClass(cls):
        try:
            file_path = cls.FILE_PATH
            os.remove(file_path)
        except FileNotFoundError:
            pass

    def test_to_read_damaged_file_and_repair(self):

        with open(self.FILE_PATH, 'wb') as file:

            TsFileGeneratorForTest.write_file_with_one_incomplete_chunk_header(file)

        reader = TsFileRestorableReader(self.FILE_PATH, True)
        tail_magic = reader.read_tail_magic()
        reader.close()

        # Check if the file was repaired
        self.assertEqual(TSFileConfig.MAGIC_STRING, tail_magic)
        os.remove(self.FILE_PATH)


    def test_to_read_damaged_file_no_repair(self):

        with open(self.FILE_PATH, 'wb') as file:

            TsFileGeneratorForTest.write_file_with_one_incomplete_chunk_header(file)

        try:
            reader = TsFileRestorableReader(self.FILE_PATH, False)
            self.assertFalse(reader.is_complete())
        except Exception as e:
            print(f"Error: {e}")
