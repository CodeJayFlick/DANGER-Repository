import unittest
from pyiotdb import IoTDBConnection

class TestIoTDBKillQuery(unittest.TestCase):

    def setUp(self):
        self.conn = IoTDBConnection("127.0.0.1", 6667, "root", "root")

    def tearDown(self):
        self.conn.close()

    def test_kill_query_test1(self):
        try:
            with self.conn.cursor() as cursor:
                cursor.execute("kill query 998")
            self.fail("QueryIdNotExistException is not thrown")
        except Exception as e:
            print(e)

    def test_kill_query_test2(self):
        try:
            with self.conn.cursor() as cursor:
                cursor.execute("kill query")
                self.assertFalse(cursor._has_result)
        except Exception as e:
            print(e)


if __name__ == '__main__':
    unittest.main()
