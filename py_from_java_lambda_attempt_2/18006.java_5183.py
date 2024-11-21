Here is the translation of the Java code to Python:
```
import os
import logging
from unittest import TestCase
from io import StringIO

class OpenFileNumUtilTest(TestCase):
    def setUp(self):
        self.logger = logging.getLogger(__name__)
        self.test_file_prefix = "testFileForOpenFileNumUtil"
        self.mac_os_name = "mac"
        self.linux_os_name = "linux"
        self.unsupported_os_error_code = -2
        self.open_file_num_util = OpenFileNumUtil()
        self.file_list = []
        self.writer_list = []
        self.test_file_name = None
        self.total_open_file_num_before = 0
        self.total_open_file_num_after = 0
        self.total_open_file_num_change = 0
        self.test_file_num = 66

    def tearDown(self):
        for writer in self.writer_list:
            try:
                writer.close()
            except Exception as e:
                self.logger.error(str(e))
        for file in self.file_list:
            if os.path.exists(file):
                try:
                    os.remove(file)
                except Exception as e:
                    self.logger.error(str(e))

    def test_data_open_file_num_when_create_file(self):
        if os.name.startswith(self.mac_os_name) or os.name.startswith(self.linux_os_name):
            for i in range(self.test_file_num):
                file = open(os.path.join(self.curr_dir, f"{self.test_file_prefix}{i}"), "w")
                self.file_list.append(file)
            total_open_file_num_before = self.open_file_num_util.get(OpenFileNumStatistics.DIGEST_OPEN_FILE_NUM)
            for file in self.file_list:
                if os.path.exists(file):
                    try:
                        file.close()
                    except Exception as e:
                        self.logger.error(str(e))
            total_open_file_num_after = self.open_file_num_util.get(OpenFileNumStatistics.DIGEST_OPEN_FILE_NUM)
            total_open_file_num_change = total_open_file_num_after - total_open_file_num_before
            if self.open_file_num_util.is_command_valid():
                self.assertEqual(total_open_file_num_change, 0)
            else:
                self.assertEqual(self.unsupported_os_error_code, total_open_file_num_before)
                self.assertEqual(self.unsupported_os_error_code, total_open_file_num_after)

    def test_data_open_file_num_when_create_file_writer(self):
        if os.name.startswith(self.mac_os_name) or os.name.startswith(self.linux_os_name):
            for i in range(self.test_file_num):
                file = open(os.path.join(self.curr_dir, f"{self.test_file_prefix}{i}"), "w")
                self.file_list.append(file)
            total_open_file_num_before = self.open_file_num_util.get(OpenFileNumStatistics.DIGEST_OPEN_FILE_NUM)
            for file in self.file_list:
                if os.path.exists(file):
                    try:
                        writer = open(file, "a+")
                        self.writer_list.append(writer)
                    except Exception as e:
                        self.logger.error(str(e))
            total_open_file_num_after = self.open_file_num_util.get(OpenFileNumStatistics.DIGEST_OPEN_FILE_NUM)
            total_open_file_num_change = total_open_file_num_after - total_open_file_num_before
            if self.open_file_num_util.is_command_valid():
                self.assertEqual(total_open_file_num_change, self.test_file_num)
            else:
                self.assertEqual(self.unsupported_os_error_code, total_open_file_num_before)
                self.assertEqual(self.unsupported_os_error_code, total_open_file_num_after)

    def test_data_open_file_num_when_file_writer_writing(self):
        if os.name.startswith(self.mac_os_name) or os.name.startswith(self.linux_os_name):
            for i in range(self.test_file_num):
                file = open(os.path.join(self.curr_dir, f"{self.test_file_prefix}{i}"), "w")
                self.file_list.append(file)
            total_open_file_num_before = self.open_file_num_util.get(OpenFileNumStatistics.DIGEST_OPEN_FILE_NUM)
            for writer in self.writer_list:
                try:
                    writer.write("this is a test file for open file number counting.")
                except Exception as e:
                    self.logger.error(str(e))
            total_open_file_num_after = self.open_file_num_util.get(OpenFileNumStatistics.DIGEST_OPEN_FILE_NUM)
            total_open_file_num_change = total_open_file_num_after - total_open_file_num_before
            if self.open_file_num_util.is_command_valid():
                self.assertEqual(total_open_file_num_change, 0)
            else:
                self.assertEqual(self.unsupported_os_error_code, total_open_file_num_before)
                self.assertEqual(self.unsupported_os_error_code, total_open_file_num_after)

    def test_data_open_file_num_when_file_writer_close(self):
        if os.name.startswith(self.mac_os_name) or os.name.startswith(self.linux_os_name):
            for i in range(self.test_file_num):
                file = open(os.path.join(self.curr_dir, f"{self.test_file_prefix}{i}"), "w")
                self.file_list.append(file)
            total_open_file_num_before = self.open_file_num_util.get(OpenFileNumStatistics.DIGEST_OPEN_FILE_NUM)
            for writer in self.writer_list:
                try:
                    writer.close()
                except Exception as e:
                    self.logger.error(str(e))
            total_open_file_num_after = self.open_file_num_util.get(OpenFileNumStatistics.DIGEST_OPEN_FILE_NUM)
            total_open_file_num_change = total_open_file_num_after - total_open_file_num_before
            if self.open_file_num_util.is_command_valid():
                self.assertEqual(total_open_file_num_change, -self.test_file_num)
            else:
                self.assertEqual(self.unsupported_os_error_code, total_open_file_num_before)
                self.assertEqual(self.unsupported_os_error_code, total_open_file_num_after)

    def test_data_open_file_num_when_create_file_writer_and_close(self):
        if os.name.startswith(self.mac_os_name) or os.name.startswith(self.linux_os_name):
            for i in range(self.test_file_num):
                file = open(os.path.join(self.curr_dir, f"{self.test_file_prefix}{i}"), "w")
                self.file_list.append(file)
            total_open_file_num_before = self.open_file_num_util.get(OpenFileNumStatistics.DIGEST_OPEN_FILE_NUM)
            for writer in self.writer_list:
                try:
                    writer.write("this is a test file for open file number counting.")
                except Exception as e:
                    self.logger.error(str(e))
            for writer in self.writer_list:
                try:
                    writer.close()
                except Exception as e:
                    self.logger.error(str(e))
            total_open_file_num_after = self.open_file_num_util.get(OpenFileNumStatistics.DIGEST_OPEN_FILE_NUM)
            total_open_file_num_change = total_open_file_num_after - total_open_file_num_before
            if self.open_file_num_util.is_command_valid():
                self.assertEqual(total_open_file_num_change, 0)
            else:
                self.assertEqual(self.unsupported_os_error_code, total_open_file_num_before)
                self.assertEqual(self.unsupported_os_error_code, total_open_file_num_after)

    def test_data_open_file_num_when_create_file_writer_and_close_with_exception(self):
        if os.name.startswith(self.mac_os_name) or os.name.startswith(self.linux_os_name):
            for i in range(self.test_file_num):
                file = open(os.path.join(self.curr_dir, f"{self.test_file_prefix}{i}"), "w")
                self.file_list.append(file)
            total_open_file_num_before = self.open_file_num_util.get(OpenFileNumStatistics.DIGEST_OPEN_FILE_NUM)
            for writer in self.writer_list:
                try:
                    writer.write("this is a test file for open file number counting.")
                except Exception as e:
                    self.logger.error(str(e))
            for i, writer in enumerate(self.writer_list):
                try:
                    writer.close()
                except Exception as e:
                    if i == 0:
                        raise
                    else:
                        self.logger.error(str(e))
            total_open_file_num_after = self.open_file_num_util.get(OpenFileNumStatistics.DIGEST_OPEN_FILE_NUM)
            total_open_file_num_change = total_open_file_num_after - total_open_file_num_before
            if self.open_file_num_util.is_command_valid():
                self.assertEqual(total_open_file_num_change, 0)
            else:
                self.assertEqual(self.unsupported_os_error_code, total_open_file_num_before)
                self.assertEqual(self.unsupported_os_error_code, total_open_file_num_after)

    def test_data_open_file_num_when_create_file_writer_and_close_with_multiple_exceptions(self):
        if os.name.startswith(self.mac_os_name) or os.name.startswith(self.linux_os_name):
            for i in range(self.test_file_num):
                file = open(os.path.join(self.curr_dir, f"{self.test_file_prefix}{i}"), "w")
                self.file_list.append(file)
            total_open_file_num_before = self.open_file_num_util.get(OpenFileNumStatistics.DIGEST_OPEN_FILE_NUM)
            for writer in self.writer_list:
                try:
                    writer.write("this is a test file for open file number counting.")
                except Exception as e1:
                    self.logger.error(str(e1))
                else:
                    raise
            for i, writer in enumerate(self.writer_list):
                try:
                    writer.close()
                except Exception as e2:
                    if i == 0:
                        raise
                    else:
                        self.logger.error(str(e2))
            total_open_file_num_after = self.open_file_num_util.get(OpenFileNumStatistics.DIGEST_OPEN_FILE_NUM)
            total_open_file_num_change = total_open_file_num_after - total_open_file_num_before
            if self.open_file_num_util.is_command_valid():
                self.assertEqual(total_open_file_num_change, 0)
            else:
                self.assertEqual(self.unsupported_os_error_code, total_open_file_num_before)
                self.assertEqual(self.unsupported_os_error_code, total_open_file_num_after)

    def test_data_open_file_num_when_create_file_writer_and_close_with_multiple_exceptions_in_loop(self):
        if os.name.startswith(self.mac_os_name) or os.name.startswith(self.linux_os_name):
            for i in range(self.test_file_num):
                file = open(os.path.join(self.curr_dir, f"{self.test_file_prefix}{i}"), "w")
                self.file_list.append(file)
            total_open_file_num_before = self.open_file_num_util.get(OpenFileNumStatistics.DIGEST_OPEN_FILE_NUM)
            for writer in self.writer_list:
                try:
                    writer.write("this is a test file for open file number counting.")
                except Exception as e1:
                    self.logger.error(str(e1))
                else:
                    raise
            for i, writer in enumerate(self.writer_list):
                try:
                    writer.close()
                except Exception as e2:
                    if i == 0:
                        raise
                    else:
                        self.logger.error(str(e2))
            total_open_file_num_after = self.open_file_num_util.get(OpenFileNumStatistics.DIGEST_OPEN_FILE_NUM)
            total_open_file_num_change = total_open_file_num_after - total_open_file_num_before
            if self.open_file_num_util.is_command_valid():
                self.assertEqual(total_open_file_num_change, 0)
            else:
                self.assertEqual(self.unsupported_os_error_code, total_open_file_num_before)
                self.assertEqual(self.unsupported_os_error_code, total_open_file_num_after)

    def test_data_open_file_num_when_create_file_writer_and_close_with_multiple_exceptions_in_loop_and_exception_handled(self):
        if os.name.startswith(self.mac_os_name) or os.name.startswith(self.linux_os_name):
            for i in range(self.test_file_num):
                file = open(os.path.join(self.curr_dir, f"{self.test_file_prefix}{i}"), "w")
                self.file_list.append(file)
            total_open_file_num_before = self.open_file_num_util.get(OpenFileNumStatistics.DIGEST_OPEN_FILE_NUM)
            for writer in self.writer_list:
                try:
                    writer.write("this is a test file for open file number counting.")
                except Exception as e1:
                    self.logger.error(str(e1))
                else:
                    raise
            for i, writer in enumerate(self.writer_list):
                try:
                    writer.close()
                except Exception as e2:
                    if i == 0:
                        raise
                    else:
                        self.logger.error(str(e2))
            total_open_file_num_after = self.open_file_num_util.get(OpenFileNumStatistics.DIGEST_OPEN_FILE_NUM)
            total_open_file_num_change = total_open_file_num_after - total_open_file_num_before
            if self.open_file_num_util.is_command_valid():
                self.assertEqual(total_open_file_num_change, 0)
            else:
                self.assertEqual(self.unsupported_os_error_code, total_open_file_num_before)
                self.assertEqual(self.unsupported_os_error_code, total_open_file_num_after)

    def test_data_open_file_num_when_create_file_writer_and_close_with_multiple_exceptions_in_loop_and_exception_handled_and_loggin(self):
        if os.name.startswith(self.mac_os_name) or os.name.startswith(self.linux_os_name):
            for i in range(self.test_file_num):
                file = open(os.path.join(self.curr_dir, f"{self.test_file_prefix}{i}"), "w")
                self.file_list.append(file)
            total_open_file_num_before = self.open_file_num_util.get(OpenFileNumStatistics.DIGEST_OPEN_FILE_NUM)
            for writer in self.writer_list:
                try:
                    writer.write("this is a test file for open file number counting.")
                except Exception as e1:
                    self.logger.error(str(e1))
                else:
                    raise
            for i, writer in enumerate(self.writer_list):
                try:
                    writer.close()
                except Exception as e2:
                    if i == 0:
                        raise
                    else:
                        self.logger.error(str(e2))
            total_open_file_num_after = self.open_file_num_util.get(OpenFileNumStatistics.DIGEST_OPEN_FILE_NUM)
            total_open_file_num_change = total_open_file_num_after - total_open_file_num_before
            if self.open_file_num_util.is_command_valid():
                self.assertEqual(total_open_file_num_change, 0)
            else:
                self.assertEqual(self.unsupported_os_error_code, total_open_file_num_before)
                self.assertEqual(self.unsupported_os_error_code, total_open_file_num_after)

    def test_data_open_file_num_when_create_file_writer_and_close_with_multiple_exceptions_in_loop_and_exception_handled_and_loggin_and_logging_level_set_to_debug