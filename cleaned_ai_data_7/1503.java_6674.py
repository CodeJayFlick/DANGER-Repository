import unittest
from ghidra.util import SystemUtilities


class SSHJoinModelForGDBSessionLauncherTest(unittest.TestCase):

    def setUp(self):
        self.assertFalse(SystemUtilities.is_in_testing_batch_mode())

    def test_model_host(self):
        return SshJoinGdbModelHost()


if __name__ == '__main__':
    unittest.main()
