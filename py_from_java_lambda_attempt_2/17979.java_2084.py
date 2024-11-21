Here is the translation of the given Java code into Python:

```Python
import unittest
from io import StringIO
import time
import mysql.connector
from datetime import datetime

class MQTTSinkTest(unittest.TestCase):

    def setUp(self):
        IoTDBDescriptor.getInstance().getConfig().setEnableMQTTService(True)
        EnvironmentUtils.envSetUp()

    def tearDown(self):
        EnvironmentUtils.cleanEnv()

    @unittest.skip("This test is not implemented in Python")
    def test_onEventUsingSingleSensorHandler(self):
        mqtt_handler = MQTTHandler()
        mqtt_config = MQTTConfiguration("127.0.0.1", 1883, "root", "root",
                                        PartialPath("root.sg1.d1"), ["s1"])
        mqtt_handler.open(mqtt_config)

        for i in range(10000):
            event = MQTTEvent("test", QoS.EXACTLY_ONCE, False, i, i)
            mqtt_handler.on_event(event)

        mqtt_handler.close()

        time.sleep(1000)

        try:
            cnx = mysql.connector.connect(user='root', password='root',
                                          host='127.0.0.1', database='iotdb')
            cursor = cnx.cursor()
            cursor.execute("SELECT * FROM root.sg1.d1")
            result = cursor.fetchall()

            for row in result:
                self.assertEqual(row[3], i)

        except mysql.connector.Error as err:
            print(err)
            self.fail(str(err))

    @unittest.skip("This test is not implemented in Python")
    def test_onEventUsingMultiSensorsHandler(self):
        mqtt_handler = MQTTHandler()
        mqtt_config = MQTTConfiguration("127.0.0.1", 1883, "root", "root",
                                        PartialPath("root.sg1.d1"), ["s1", "s2", "s3", "s4", "s5", "s6"])
        mqtt_handler.open(mqtt_config)

        for i in range(10000):
            event = MQTTEvent("test", QoS.EXACTLY_ONCE, False, i, i,
                               int(i), float(i), float(i), bool(i % 2 == 0), str(i))
            mqtt_handler.on_event(event)

        mqtt_handler.close()

        time.sleep(1000)

        try:
            cnx = mysql.connector.connect(user='root', password='root',
                                          host='127.0.0.1', database='iotdb')
            cursor = cnx.cursor()
            cursor.execute("SELECT * FROM root.sg1.d1")
            result = cursor.fetchall()

            for row in result:
                self.assertEqual(row[3], i)

        except mysql.connector.Error as err:
            print(err)
            self.fail(str(err))

    def check_header(self, resultSetMetaData, expectedHeaderStrings, expectedTypes):
        expected_headers = expectedHeaderStrings.split(",")
        expected_header_to_type_index_map = {}

        for i in range(len(expected_headers)):
            expected_header_to_type_index_map[expected_headers[i]] = i

        for i in range(1, len(resultSetMetaData.column_names) + 1):
            type_index = expected_header_to_type_index_map.get(resultSetMetaData.get_column_name(i))
            self.assertIsNotNone(type_index)
            self.assertEqual(expectedTypes[type_index], resultSetMetaData.get_column_type(i))

if __name__ == '__main__':
    unittest.main()
```

Please note that the `MQTTHandler` and `EnvironmentUtils` classes are not implemented in Python, so you would need to implement them or replace them with equivalent functionality.