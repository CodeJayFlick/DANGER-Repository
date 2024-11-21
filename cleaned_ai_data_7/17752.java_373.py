import unittest
from threading import Thread
import time


class MergeManagerTest(unittest.TestCase):

    def test_rate_limiter(self):
        compaction_rate_limiter = MergeManager().get_merge_write_rate_limiter()
        start_time = time.time()
        MergeManager.merge_rate_limiter_acquire(compaction_rate_limiter, 160 * 1024 * 1024)
        self.assertLessEqual(time.time() - start_time, 1.0)  # Assuming the rate limiter takes at most 1 second
        MergeManager.merge_rate_limiter_acquire(compaction_rate_limiter, 16 * 1024 * 1024)
        self.assertGreaterEqual(time.time() - start_time, 9.0)

    def check_report(self, report):
        lines = report.split('\n')
        self.assertEqual(lines[0], 'Main tasks:')
        self.assertEqual(lines[1], '\tStorage group: test')
        for i in range(5):
            task_name = f'task{i}'
            self.assertIn(task_name, lines[i + 2])
            self.assertIn('0,', lines[i + 2])
            self.assertIn('done:false', lines[i + 2])
            self.assertIn('cancelled:false', lines[i + 2])

        self.assertEqual(lines[7], 'Sub tasks:')
        self.assertEqual(lines[8], '\tStorage group: test')
        for i in range(5):
            task_name = f'task{i}'
            self.assertIn(task_name, lines[i + 9])
            self.assertIn('0,', lines[i + 9])
            self.assertIn('done:false', lines[i + 9])
            self.assertIn('cancelled:false', lines[i + 9])


class FakedMainMergeTask:
    def __init__(self, serial_num):
        super().__init__()
        self.serial_num = serial_num
        self.progress = '0'

    def call(self):
        while not Thread.current_thread().is_alive():
            pass
        self.progress = '1'
        return None

    def get_storage_group_name(self):
        return 'test'

    def get_progress(self):
        return self.progress

    def get_task_name(self):
        return f'task{self.serial_num}'


class FakedMergeMultiChunkTask:
    def __init__(self):
        super().__init__()

    def create_sub_task(self, serial_num):
        return FakedSubMergeTask(serial_num)


class FakedSubMergeTask(FakedMergeMultiChunkTask):
    def __init__(self, serial_num):
        super().__init__()
        self.serial_num = serial_num
        self.progress = '0'

    def call(self):
        while not Thread.current_thread().is_alive():
            pass
        self.progress = '1'
        return None

    def get_storage_group_name(self):
        return 'test'

    def get_progress(self):
        return self.progress

    def get_task_name(self):
        return f'task{self.serial_num}'


if __name__ == '__main__':
    unittest.main()
