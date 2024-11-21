import unittest
from datetime import datetime

class AsyncInitializationWrapperTest(unittest.TestCase):

    def test_init_create_no_start_time_sets_current_time(self):
        init = AsyncInitializationWrapper()
        start_time = int(datetime.now().timestamp())
        self.assertEqual(start_time, init.get_actual_start_time_ms())

    def test_init_create_with_start_time_stores_custom_start_time(self):
        start_time = int(datetime.now().timestamp())
        import time
        time.sleep(0.5)  # equivalent to Thread.sleep(500)
        init = AsyncInitializationWrapper(start_time)

        self.assertEqual(start_time, init.get_actual_start_time_ms())

if __name__ == '__main__':
    unittest.main()
