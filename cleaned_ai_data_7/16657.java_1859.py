import unittest
from io import StringIO
import sys

class SingleNodeTest(unittest.TestCase):

    def setUp(self):
        pass  # This method should be implemented based on your actual setup requirements.

    def tearDown(self):
        pass  # This method should be implemented based on your actual teardown requirements.

    @unittest.skip("This test is not yet implemented.")
    def test_insert_records_with_illegal_path(self):

        device_ids = ["root..ln1", "root.sg.ln1", "root..ln1", "root.sg3.ln1"]
        timestamps = [3, 3, 3, 3]
        measurements = ["dev1", "dev2", "dev3"]
        all_measurements = [[measurement] for measurement in measurements] * 4
        values = ["123", "333", "444"]
        all_values = [[value] for value in values] * 4

        try:
            # This line should be implemented based on your actual database operations.
            session.insert_records(device_ids, timestamps, all_measurements, all_values)
            self.fail("Exception expected")
        except StatementExecutionException as e:
            self.assertTrue(e.get_message().contains("root..ln1 is not a legal path"))

        legal_devices = ["root.sg.ln1", "root.sg3.ln1"]
        for device in legal_devices:
            for measurement in measurements:
                self.assertTrue(session.check_timeseries_exists(device + IoTDBConstant.PATH_SEPARATOR + measurement))

    @unittest.skip("This test is not yet implemented.")
    def test_delete_non_exist_time_series(self):

        session.insert_record(
            "root.sg1.d1", 0, ["t1", "t2", "t3"], ["123", "333", "444"]
        )
        session.delete_timeseries(["root.sg1.d1.t6", "root.sg1.d1.t2", "root.sg1.d1.t3"])

        self.assertTrue(session.check_timeseries_exists("root.sg1.d1.t1"))
        self.assertFalse(session.check_timeseries_exists("root.sg1.d1.t2"))
        self.assertFalse(session.check_timeseries_exists("root.sg1.d1.t3"))

    @unittest.skip("This test is not yet implemented.")
    def test_user_privilege(self):

        try:
            # This line should be implemented based on your actual database operations.
            connection = DriverManager.getConnection(
                Config.IOTDB_URL_PREFIX + "127.0.0.1:6667/", "root", "root"
            )
            statement = connection.createStatement()
            statement.execute("create user user1 '1234'")

            try:
                # This line should be implemented based on your actual database operations.
                connection1 = DriverManager.getConnection(
                    Config.IOTDB_URL_PREFIX + "127.0.0.1:6667/", "user1", "1234"
                )
                statement1 = connection1.createStatement()
                statement1.addBatch("create timeseries root.sg1.d1.s1 with datatype=int32")
                statement1.addBatch(
                    "create timeseries root.sg2.d1.s1 with datatype=int32"
                )
                statement1.executeBatch()

            except Exception as e:
                self.assertEqual(
                    System.lineSeparator()
                    + "No permissions for this operation CREATE_TIMESERIES "
                    + "for SQL: \"create timeseries root.sg1.d1.s1 with datatype=int32\""
                    + System.lineSeparator()
                    + "No permissions for this operation CREATE_TIMESERIES "
                    + "for SQL: \"create timeseries root.sg2.d1.s1 with datatype=int32\""
                    + System.lineSeparator(),
                    e.get_message()
                )

        except Exception as e:
            self.fail(e.get_message())

if __name__ == "__main__":
    unittest.main()
