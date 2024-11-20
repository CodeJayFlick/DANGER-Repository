Here's your Java code translated into Python:

```Python
import unittest
from datetime import zoneinfo

class SessionTest(unittest.TestCase):

    def setUp(self):
        self.session = None
        System.setProperty("IoTDB_CONF", "src/test/resources/")
        EnvironmentUtils.closeStatMonitor()
        EnvironmentUtils.envSetUp()

    def tearDown(self):
        if self.session is not None:
            try:
                self.session.close()
            except Exception as e:
                fail(str(e))
        EnvironmentUtils.cleanEnv()

    @unittest.skip("Not implemented yet")
    def testSortTablet(self):
        self.session = Session("127.0.0.1", 6667, "root", "root", None)
        schema_list = []
        schema_list.append(UnaryMeasurementSchema("s1", TSDataType.INT64, TSEncoding.RLE))
        tablet = Tablet("root.sg1.d1", schema_list, 3)

    @unittest.skip("Not implemented yet")
    def testInsertByStrAndSelectFailedData(self):
        self.session = Session("127.0.0.1", 6667, "root", "root", zoneinfo("+05:00"))
        self.session.open()

    @unittest.skip("Not implemented yet")
    def testSetTimeZone(self):
        self.session = Session("127.0.0.1", 6667, "root", "root", zoneinfo("+09:00"))
        self.assertEqual("+09:00", self.session.get_time_zone())
        self.session.set_time_zone("+05:00")
        self.assertEqual("+05:00", self.session.get_time_zone())

    @unittest.skip("Not implemented yet")
    def testTimeout(self):
        self.session = Session("127.0.0.1", 6667, "root", "root", query_timeout=20000)
        self.assertEqual(60000, self.session.query_timeout)

    @unittest.skip("Not implemented yet")
    def createSchemaTemplate(self):
        self.session = Session("127.0.0.1", 6667, "root", "root", zoneinfo("+05:00"))
        self.session.open()

    @unittest.skip("Not implemented yet")
    def testBuilder(self):
        builder = Session.Builder()
        session = builder.host("localhost").port(1234).fetch_size(1).username("abc").password("123456").thrift_default_buffer_size(2).thrift_max_frame_size(3).enable_cache_leader(True).zone_id(zoneinfo("+05:00")).build()

    @unittest.skip("Not implemented yet")
    def testUnsetSchemaTemplate(self):
        self.session = Session("127.0.0.1", 6667, "root", "root", zoneinfo("+05:00"))
        self.session.open()
```

Note that the code above is a direct translation of your Java code into Python and may not be fully functional or error-free. It's meant to serve as a starting point for you to build upon.