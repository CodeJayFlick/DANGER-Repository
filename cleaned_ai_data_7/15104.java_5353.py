import os
import unittest

class AppTest(unittest.TestCase):

    def test_execute_without_exception(self):
        try:
            import app  # Assuming your application file name is 'app.py'
            app.main([])
        except Exception as e:
            self.fail(f"An exception occurred: {e}")

    @classmethod
    def setUpClass(cls):
        for filename in ["fish1.out", "fish2.out"]:
            if os.path.exists(filename):
                os.remove(filename)

    @classmethod
    def tearDownClass(cls):
        pass

if __name__ == '__main__':
    unittest.main()
