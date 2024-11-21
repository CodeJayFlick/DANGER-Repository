import unittest
from unittest.mock import patch

class TestApp(unittest.TestCase):

    @unittest.skipIf(sys.version_info < (3, 7), "Requires Python 3.7 or higher")
    def test_app(self):
        with patch('sys.argv', ['']):
            assert not App().main([])

if __name__ == '__main__':
    unittest.main()
