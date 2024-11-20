Here is the translation of the Java code into Python:

```Python
import unittest
from datetime import date, timedelta
from io import BytesIO
import random
import struct

class DeltaBinaryEncoderLongTest(unittest.TestCase):

    ROW_NUM = 10000
    BASIC_FACTOR = (1 << 32)

    def setUp(self):
        self.writer = DeltaBinaryEncoder.LongDeltaEncoder()
        self.reader = DeltaBinaryDecoder.LongDeltaDecoder()

    def testBasic(self):
        data = [i * i * self.BASIC_FACTOR for i in range(ROW_NUM)]
        self.shouldReadAndWrite(data, ROW_NUM)

    def testBoundInt(self):
        data = []
        for _ in range(ROW_NUM):
            power = random.randint(2, 20)
            value = (random.randint((1 << power) - 1)) * self.BASIC_FACTOR
            data.append(value)
        self.shouldReadAndWrite(data, ROW_NUM)

    def testRandom(self):
        data = [random.getrandbits(64) * self.BASIC_FACTOR for _ in range(ROW_NUM)]
        self.shouldReadAndWrite(data, ROW_NUM)

    def testMaxMin(self):
        data = [(i & 1) == 0 and (2**63 - 1) or (-2**63 + 1) for i in range(ROW_NUM)]
        self.shouldReadAndWrite(data, ROW_NUM)

    def testRegularEncoding(self):
        start_date = date.fromisoformat('1970-01-08')
        end_date = date.fromisoformat('1978-01-08')

        dates = []
        current_date = start_date
        while current_date <= end_date:
            dates.append(current_date.isoformat())
            current_date += timedelta(days=1)

        ROW_NUM = len(dates)
        data = [date.timestamp() for date in map(date.fromisoformat, dates)]
        self.shouldReadAndWrite(data, ROW_NUM)

    def testRegularWithMissingPoints(self):
        start_date = date.fromisoformat('1970-01-08')
        end_date = date.fromisoformat('1978-01-08')

        dates = []
        current_date = start_date
        while current_date <= end_date:
            if (current_date - start_date).days % 500 == 0:
                continue
            dates.append(current_date.isoformat())
            current_date += timedelta(days=1)

        ROW_NUM = len(dates)
        data = [date.timestamp() for date in map(date.fromisoformat, dates)]
        self.shouldReadAndWrite(data, ROW_NUM)

    def shouldReadAndWrite(self, data, length):
        out = BytesIO()
        write_data(out, data[:length])
        page = out.getvalue()
        buffer = memoryview(page)
        i = 0
        while self.reader.has_next(buffer):
            self.assertEqual(data[i], struct.unpack('<q', buffer.read(8))[0])
            i += 1

    def get_between_date(self, start, end):
        list_ = []
        start_date = date.fromisoformat(start)
        end_date = date.fromisoformat(end)

        distance = (end_date - start_date).days
        if distance < 1:
            return list_

        for _ in range(distance + 1):
            yield start_date.isoformat()
            start_date += timedelta(days=1)


    def write_data(self, data, length):
        out = BytesIO()
        for i in range(length):
            self.writer.encode(data[i], out)
        self.writer.flush(out)

if __name__ == '__main__':
    unittest.main()
```

Please note that Python does not have direct equivalent of Java's `@Before` and `@Test`. The setup method is used to initialize the test data.