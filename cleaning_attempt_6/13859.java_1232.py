import unittest
from unittest.mock import patch

class TestApp(unittest.TestCase):

    @patch('builtins.print')
    def test_app(self, mock_print):
        try:
            App.main([])
        except Exception as e:
            self.fail(f"Expected no exception but got {e}")
        else:
            pass  # No assertion needed if the function doesn't throw an exception

if __name__ == '__main__':
    unittest.main()
