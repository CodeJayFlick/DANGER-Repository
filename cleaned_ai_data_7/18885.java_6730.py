import unittest
from unittest.mock import patch

class AbstractTestJerseyRest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.database_adapter = DatabaseAdapter()

    @patch('org.projectnessie.jaxrs.NessieJaxRsExtension')
    def setUp(self, mock_extension):
        self.server = mock_extension.return_value
        self.server.get_uri.return_value = 'http://example.com'

    def test_something(self):
        # Your test code here

if __name__ == '__main__':
    unittest.main()
