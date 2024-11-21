import unittest
from datetime import datetime as dt
from time import sleep

class IoTDBSinkBatchTimerTest(unittest.TestCase):

    def setUp(self):
        self.ioTDBSink = IoTDBSink()
        options = {"timeseriesOptionList": ["root.sg.D01.temperature"]}
        self.ioTDBSink.init(options, DefaultIoTSerializationSchema())
        self.ioTDBSink.batch_size = 3
        self.ioTDBSink.flush_interval_ms = 1000

    def test_batch_insert(self):
        tuple_data = {"device": "root.sg.D01", 
                      "timestamp": dt(2020, 2, 20).timestamp(), 
                      "measurements": "temperature", 
                      "types": "DOUBLE", 
                      "values": "36.5"}
        self.ioTDBSink.invoke(tuple_data)

        sleep(2.5) # equivalent to Thread.sleep(2500)
        
    def test_close(self):
        self.ioTDBSink.close()
