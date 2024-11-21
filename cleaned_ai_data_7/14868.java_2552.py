import unittest
from saga import SagaApplication

class TestSagaApplication(unittest.TestCase):

    def test_should_execute_without_exception(self):
        try:
            SagaApplication.main([])
        except Exception as e:
            self.fail(f"An exception occurred: {e}")

if __name__ == '__main__':
    unittest.main()
