import unittest

class TestApp(unittest.TestCase):
    def test_should_execute_application_without_exception(self):
        try:
            App.main([])
        except Exception as e:
            self.fail(f"Expected no exception, but got {e}")

if __name__ == '__main__':
    unittest.main()
