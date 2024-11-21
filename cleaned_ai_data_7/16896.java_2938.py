import unittest
from unittest.mock import patch, Mock
import timezones


class IoTDBStatementTest(unittest.TestCase):

    @patch('iotdb.IoTDBConnection')
    def setUp(self, mock_connection):
        self.connection = mock_connection
        self.client = Mock()
        self.session_id = 1234567890
        self.fetch_metadata_resp = Mock()

    def tearDown(self):
        pass

    def test_set_fetch_size1(self):
        stmt = IoTDBStatement(self.connection, self.client, self.session_id)
        stmt.set_fetch_size(123)
        self.assertEqual(stmt.get_fetch_size(), 123)

    def test_set_fetch_size2(self):
        stmt = IoTDBStatement(self.connection, self.client, self.session_id)
        initial = stmt.get_fetch_size()
        stmt.set_fetch_size(0)
        self.assertEqual(stmt.get_fetch_size(), initial)

    def test_set_fetch_size3(self):
        fetch_size = 10000
        stmt = IoTDBStatement(self.connection, self.client, self.session_id, zoneID=fetch_size)
        self.assertEqual(stmt.get_fetch_size(), fetch_size)

    @unittest.expectedFailure
    def test_set_fetch_size4(self):
        stmt = IoTDBStatement(self.connection, self.client, self.session_id)
        with self.assertRaises(SQLException):
            stmt.set_fetch_size(-1)

    def test_timeout_test(self):
        statement = IoTDBStatement(self.connection, self.client, self.session_id, timeout=60)
        self.assertEqual(60, statement.get_query_timeout())
        statement.set_query_timeout(100)
        self.assertEqual(100, statement.get_query_timeout())

if __name__ == '__main__':
    unittest.main()
