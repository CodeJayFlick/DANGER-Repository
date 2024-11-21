import unittest
from unittest.mock import patch

class TestBullyApp(unittest.TestCase):

    @unittest.skipIf(sys.platform.startswith("java"), "This test is not compatible with JUnit")
    def test_execute_application_without_exception(self):
        try:
            BullyApp.main([])
        except Exception as e:
            self.fail(f"An exception occurred: {e}")

if __name__ == '__main__':
    unittest.main()
