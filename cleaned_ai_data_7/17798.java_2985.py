import unittest
from datetime import datetime

class SysTimeVersionControllerTest(unittest.TestCase):
    def test(self):
        version_controller = SysTimeVersionController.INSTANCE
        diff = version_controller.curr_version() - int(datetime.now().timestamp())
        # avoid test failure on a poor machine, bear 200ms difference here.
        self.assertTrue(-200 <= diff <= 200)
        diff = version_controller.next_version()
        try:
            time.sleep(0.2)  # equivalent to Thread.sleep(200)
            diff -= int(datetime.now().timestamp())
            self.assertTrue(-1000 <= diff <= -200)
        except KeyboardInterrupt:  # equivalent to InterruptedException
            pass

if __name__ == '__main__':
    unittest.main()
