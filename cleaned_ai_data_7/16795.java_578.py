import unittest
from mock import patch, ANY

class IoTDBSinkInsertTest(unittest.TestCase):

    def setUp(self):
        self.ioTDBSink = None
        self.pool = None

    @patch('org.apache.iotdb.flume.sink.IoTDBSinkOptions')
    @patch('org.apache.iotdb.session.pool.SessionPool')
    def test_insert(self, session_pool_mock, iot_db_sink_options_mock):
        options = IoTDBSinkOptions()
        timeseries_option_list = [IoTDBSinkOptions.TimeseriesOption("root.sg.D01.temperature")]
        options.set_timeseries_option_list(timeseries_option_list)
        self.ioTDBSink = IoTDBSink(options, DefaultIoTSerializationSchema())
        pool_mock = session_pool_mock.return_value
        self.ioTDBSink.set_session_pool(pool_mock)

    def test_insert(self):
        tuple_ = {"device": "root.sg.D01", "timestamp": 1581861293000, 
                  "measurements": ["temperature"], "types": ["DOUBLE"], "values": [36.5]}
        self.ioTDBSink.invoke(tuple_, None)
        pool_mock.insert_record(ANY(str), ANY(int), ANY(list), ANY(list), ANY(list))

    @patch('org.apache.iotdb.flume.sink.IoTDBSink.close')
    def test_close(self, close_method):
        self.ioTDBSink.close()
        close_method.assert_called_once_with()

if __name__ == '__main__':
    unittest.main()
