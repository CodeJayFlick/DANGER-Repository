import unittest
from unittest.mock import patch

class TestApp(unittest.TestCase):

    @unittest.skipIf(sys.version_info < (3, 7), "Jupiter API not available in this version")
    def test_app_execution(self):
        with self.assertRaises(SystemExit) as cm:
            App.main([])
        assert cm.exception.code == 0
