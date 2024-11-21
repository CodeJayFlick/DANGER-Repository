import unittest
from logging import getLogger, INFO

class ConfigureForUnixVisitorTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.logger = getLogger(__name__)

    def tearDown(self):
        pass  # Clear loggers here if needed

    def test_visit_for_zoom(self):
        con_unix = ConfigureForUnixVisitor()
        zoom = Zoom()

        con_unix.visit(zoom)

        self.assertEqual(
            [event for event in self.logger.records],
            [{"levelno": INFO, "message": f"{zoom} used with Unix configurator."}]
        )

if __name__ == "__main__":
    unittest.main()
