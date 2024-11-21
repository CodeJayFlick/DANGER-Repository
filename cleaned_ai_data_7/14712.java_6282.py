import unittest
from unittest.mock import patch

class TestApp:
    @unittest.skipIf(sys.version_info < (3, 7), "JUnit Jupiter API not available in this version of Python")
    def test_app(self):
        with self.assertRaises(SystemExit) as cm:
            App.main([])
        assert cm.exception.code == 0
