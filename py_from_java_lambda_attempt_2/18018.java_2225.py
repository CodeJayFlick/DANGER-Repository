Here is the translation of the Java code to Python:

```Python
import os
from typing import Dict

class DeviceStringTest:
    def __init__(self):
        self.ts_f = None  # type: str
        self.writer = None  # type: object
        self.log_node_prefix = "testNode/0"
        self.schema = None  # type: object
        self.resource = None  # type: object
        self.m_manager = IoTDB.metaManager

    def setup(self):
        os.makedirs(os.path.dirname(self.ts_f), exist_ok=True)
        self.schema = Schema()
        self.schema.register_timeseries(
            ("root.s.g.device99", "sensor4"),
            UnaryMeasurementSchema("sensor4", TSDataType.INT64, TSEncoding.PLAIN))
        self.m_manager.create_timeseries(
            ("root.s.g.device99.sensor4"), 
            TSDataType.INT64, 
            TSEncoding.PLAIN)
        self.schema.register_timeseries(
            ("root.s.g.device99", "sensor2"),
            UnaryMeasurementSchema("sensor2", TSDataType.INT64, TSEncoding.PLAIN))
        self.m_manager.create_timeseries(
            ("root.s.g.device99.sensor2"), 
            TSDataType.INT64, 
            TSEncoding.PLAIN)
        self.schema.register_timeseries(
            ("root.s.g.device99", "sensor1"),
            UnaryMeasurementSchema("sensor1", TSDataType.INT64, TSEncoding.PLAIN))
        self.m_manager.create_timeseries(
            ("root.s.g.device99.sensor1"), 
            TSDataType.INT64, 
            TSEncoding.PLAIN)
        self.writer = TsFileWriter(self.ts_f, self.schema)

    def tearDown(self):
        os.remove(self.ts_f)
        if hasattr(self.resource, 'close'):
            self.resource.close()

    def test_device_string(self):
        self.resource = TsFileResource(self.ts_f)
        self.resource.deserialize()
        assert not self.resource.get_devices().empty
        for device in self.resource.get_devices():
            assert device == self.m_manager.get_device_id(PartialPath(device))

if __name__ == "__main__":
    DeviceStringTest().setup()
```

Please note that this is a Python translation of the Java code, and it may not be exactly equivalent. The `TSFileWriter`, `TsFileResource` classes are assumed to have similar functionality as their Java counterparts.