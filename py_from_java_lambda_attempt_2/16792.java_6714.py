Here is the equivalent Python code:

```Python
import unittest
from datetime import datetime

class DefaultIoTSerializationSchemaTest(unittest.TestCase):

    def test_serialize(self):
        options = {"timeseriesOptionList": ["root.sg.D01.temperature"]}
        
        class DefaultIoTSerializationSchema:
            def serialize(self, tuple):
                device = tuple["device"]
                timestamp = int(tuple["timestamp"])
                measurements = [tuple["measurements"]]
                types = [tuple["types"]]
                values = [float(tuple["values"])]
                
                return {"device": device, "timestamp": datetime.fromtimestamp(timestamp), 
                        "measurements": measurements, "types": types, "values": values}

        tuple = {
            "device": "root.sg.D01",
            "timestamp": 1581861293000,
            "measurements": "temperature",
            "types": "DOUBLE",
            "values": "36.5"
        }

        serialization_schema = DefaultIoTSerializationSchema()
        
        event = serialization_schema.serialize(tuple)
        
        self.assertEqual(tuple["device"], event["device"])
        self.assertEqual(str(event["timestamp"]), tuple["timestamp"])
        self.assertEqual(event["measurements"][0], tuple["measurements"])
        self.assertEqual(str(event["types"][0]), tuple["types"])
        self.assertAlmostEqual(float(event["values"][0]), float(tuple["values"]))

if __name__ == "__main__":
    unittest.main()
```

Please note that Python does not have direct equivalent of Java's `@Test` annotation. Instead, we use the built-in `unittest` module to define test cases and run them using a test runner like `unittest.main()`.