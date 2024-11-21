import unittest
from datetime import datetime, timezone, timedelta

class IoTDBsqlVisitorTest(unittest.TestCase):

    def setUp(self):
        self.visitor = None

    def tearDown(self):
        pass

    def test_parse_time_format_now(self):
        now = int(datetime.now().timestamp())
        for i in range(13):  # 0 to 12
            offset1, offset2 = None, None
            if i < 10:
                offset1 = timezone(offset=timedelta(hours=i))
                offset2 = timezone(offset=timedelta(hours=-i))
            else:
                offset1 = timezone(offset=timedelta(hours=i-10))
                offset2 = timezone(offset=timedelta(hours=-i+10))

            zoned_datetime = datetime.now().replace(tzinfo=offset1)
            self.assertEqual(now, int(zoned_datetime.timestamp()))
            zoned_datetime = datetime.now().replace(tzinfo=offset2)
            self.assertEqual(now, int(zoned_datetime.timestamp()))

    def test_parse_time_format_now_precision(self):
        time_precision = "ms"
        IoTDBDescriptor.set_timestamp_precision("ms")
        now_ms = int(datetime.now().timestamp())
        ms_str = str(now_ms)

        IoTDBDescriptor.set_timestamp_precision("us")
        now_us = int(datetime.now().timestamp())
        us_str = str(now_us)

        IoTDBDescriptor.set_timestamp_precision("ns")
        now_ns = int(datetime.now().timestamp())
        ns_str = str(now_ns)

        self.assertEqual(len(ms_str) + 3, len(us_str))
        self.assertEqual(len(us_str) + 3, len(ns_str))

    def test_parse_time_format_fail1(self):
        with self.assertRaises(ValueError):  # equivalent to expected=SQLParserException.class
            self.visitor.parse_date_format(None)

    def test_parse_time_format_fail2(self):
        with self.assertRaises(ValueError):  # equivalent to expected=SQLParserException.class
            self.visitor.parse_date_format("")

if __name__ == '__main__':
    unittest.main()
