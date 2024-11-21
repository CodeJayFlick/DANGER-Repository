Here is the equivalent Python code for the given Java file:

```Python
import unittest
from unittest.mock import patch, Mock
from datetime import zoneinfo

class IoTDBConnectionTest(unittest.TestCase):

    @patch('org.apache.iotdb.rpc.TSIService.Iface')
    def setUp(self, mock_client):
        self.client = mock_client
        self.connection = IoTDBConnection()
        self.success_status = 'SUCCESS_STATUS'
        self.session_id = None

    def tearDown(self):
        pass

    def test_set_time_zone(self):
        time_zone = "Asia/Shanghai"
        self.client.set_time_zone.return_value = {'status': self.success_status}
        self.connection.set_client(self.client)
        self.connection.set_time_zone(time_zone)
        self.assertEqual(self.connection.get_time_zone(), time_zone)

    @patch('org.apache.iotdb.rpc.TSIService.Iface')
    def test_get_time_zone(self, mock_client):
        time_zone = zoneinfo.system().zone
        session_id = 1
        self.client.get_time_zone.return_value = {'status': self.success_status, 'timeZone': time_zone}
        self.connection.set_client(mock_client)
        self.assertEqual(self.connection.get_time_zone(), time_zone)

    @patch('org.apache.iotdb.rpc.TSIService.Iface')
    def test_get_server_properties(self, mock_client):
        version = "v0.1"
        supported_aggregation_times = ["max_time", "min_time"]
        timestamp_precision = "ms"

        self.client.get_properties.return_value = {'version': version,
                                                    'supportedAggregationTime': supported_aggregation_times,
                                                    'timestampPrecision': timestamp_precision}

        self.connection.set_client(mock_client)
        self.assertEqual(self.connection.get_server_properties().get_version(), version)

        for i in range(len(supported_aggregation_times)):
            self.assertEqual(
                self.connection.get_server_properties().get_supported_time_aggregation_operations()[i],
                supported_aggregation_times[i]
            )

        self.assertEqual(self.connection.get_server_properties().get_timestamp_precision(), timestamp_precision)

    def test_set_query_timeout(self):
        self.connection.set_query_timeout(60)
        self.assertEqual(self.connection.get_query_timeout(), 60)


if __name__ == '__main__':
    unittest.main()
```

Please note that this is a Python translation of the given Java code. The actual implementation may vary depending on your specific requirements and constraints.