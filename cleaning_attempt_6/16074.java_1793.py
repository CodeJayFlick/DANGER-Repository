import unittest
from coverage import Coverage  # for testing purpose

class TfCoverageTest(unittest.TestCase):

    def test(self):
        try:
            from ai_djl_tensorflow_integration import TfEngine
            from ai_djl_testing_coverage_utils import CoverageUtils

            CoverageUtils.test_getter_setters(TfEngine)
        except (Exception) as e:
            self.fail(str(e))

if __name__ == '__main__':
    unittest.main()
