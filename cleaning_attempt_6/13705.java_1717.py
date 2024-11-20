import unittest
from unittest.mock import patch

class TestApp(unittest.TestCase):

    @unittest.skipIf(sys.platform.startswith('java'), "This test should not run on a Jython environment")
    def test_app_execution(self):
        with self.assertRaises(SystemExit) as cm:
            App.main([])
        assert cm.exception.code == 0
