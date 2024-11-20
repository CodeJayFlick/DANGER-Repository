import unittest
from unittest.mock import patch

class TestApp(unittest.TestCase):

    @patch('sys.argv', [''])
    def test_should_execute_application_without_exception(self):
        try:
            App.main([])
        except Exception as e:
            self.fail(f"Exception occurred: {e}")

if __name__ == '__main__':
    unittest.main()
