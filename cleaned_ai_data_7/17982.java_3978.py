import os
import unittest
from io import BufferedReader, FileReader


class SyncReceiverLoggerTest(unittest.TestCase):

    def setUp(self):
        self.receiver_logger = None
        self.data_dir = EnvironmentUtils.env_set_up()

    def tearDown(self):
        EnvironmentUtils.clean_env()

    @unittest.skipIf(os.name != 'posix', "Only works on Unix-based systems")
    def test_sync_receiver_logger(self):
        receiver_logger = SyncReceiverLogger(
            os.path.join(self.data_dir, SyncConstant.SYNC_LOG_NAME)
        )
        deleted_file_names = set()
        to_be_synced_files = set()

        receiver_logger.start_sync_deleted_files_name()
        for i in range(200):
            file_path = f"deleted{i}"
            receiver_logger.finish_sync_deleted_file_name(os.path.join(self.data_dir, "127.0.0.1_5555", file_path))
            deleted_file_names.add(file_path)

        receiver_logger.start_sync_ts_files()
        for i in range(200):
            file_path = f"new{i}"
            receiver_logger.finish_sync_tsfile(os.path.join(self.data_dir, "127.0.0.1_5555", file_path))
            to_be_synced_files.add(file_path)

        receiver_logger.close()

        count = 0
        mode = 0

        with open(os.path.join(self.data_dir, SyncConstant.SYNC_LOG_NAME), 'r') as f:
            br = BufferedReader(FileredReader(f))

            line = br.readline()
            while line is not None:
                if line == SyncReceiverLogger.SYNC_DELETED_FILE_NAME_START:
                    mode = -1
                elif line == SyncReceiverLogger.SYNC_TSFILE_START:
                    mode = 1
                else:
                    if mode == -1:
                        deleted_file_names.add(line)
                    elif mode == 1:
                        to_be_synced_files.add(line)

                count += 1

        self.assertEqual(402, count)
        self.assertEqual(len(deleted_file_names), len(set(deleted_file_names)))
        self.assertEqual(len(to_be_synced_files), len(set(to_be_synced_files)))
        self.assertTrue(deleted_file_names.issuperset(set(deleted_file_names)))
        self.assertTrue(to_be_synced_files.issuperset(set(to_be_synced_files)))


if __name__ == '__main__':
    unittest.main()
