import unittest
from unittest.mock import patch

class TestApp(unittest.TestCase):

    @unittest.skip("This test needs implementation")
    def test_app(self):
        with self.assertRaises(SystemExit) as cm:
            App.main([])
        assert cm.exception.code == 0


if __name__ == '__main__':
    unittest.main()
