import os
from unittest import TestCase, main


class AppTest(TestCase):

    def test_should_execute_application_without_exception(self):
        try:
            App.main([])
        except Exception as e:
            self.fail(f"An exception occurred: {e}")

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass


if __name__ == "__main__":
    main()
