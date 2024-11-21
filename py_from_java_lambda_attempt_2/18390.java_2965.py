Here is the translation of the Java code to Python:

```Python
import unittest
from enum import Enum

class TSDataType(Enum):
    INT32 = 1


class BatchData:
    def __init__(self, data_type: TSDataType):
        self.data_type = data_type
        self.values = []

    def put_an_object(self, time: int, value: int) -> None:
        self.values.append((time, value))

    def get_data_type(self) -> TSDataType:
        return self.data_type

    def has_current(self) -> bool:
        return len(self.values) > 0

    def current_time(self) -> int:
        if not self.has_current():
            raise ValueError("No more values")
        return self.values[0][0]

    def current_value(self) -> int:
        if not self.has_current():
            raise ValueError("No more values")
        return self.values[0][1]

    def next(self) -> None:
        if not self.has_current():
            raise ValueError("No more values")
        del self.values[0]

    def reset_batch_data(self) -> None:
        pass

class IPointReader:
    def __init__(self, batch_data: BatchData):
        self.batch_data = batch_data
        self.index = 0

    def has_next_timeValuePair(self) -> bool:
        return len(self.batch_data.values) > self.index

    def next_timeValuePair(self) -> tuple[int, int]:
        if not self.has_next_timeValuePair():
            raise ValueError("No more values")
        time_value_pair = self.batch_data.values[self.index]
        self.index += 1
        return time_value_pair


class TestBatchData(unittest.TestCase):
    def test_int(self) -> None:
        batch_data = BatchData(TSDataType.INT32)
        self.assertTrue(batch_data.has_current())
        value = 0
        for time in range(10):
            batch_data.put_an_object(time, value)
            value += 1

        self.assertEqual(TSDataType(INT32), batch_data.get_data_type())

        res = 0
        time = 0
        while batch_data.has_current():
            self.assertEqual(time, batch_data.current_time())
            self.assertEqual(res, batch_data.current_value())
            batch_data.next()
            res += 1
            time += 1

        batch_data.reset_batch_data()

        reader = IPointReader(batch_data)
        try:
            res = 0
            time = 0
            while reader.has_next_timeValuePair():
                time_value_pair = reader.next_timeValuePair()
                self.assertEqual(time, time_value_pair[0])
                self.assertEqual(res, time_value_pair[1])
                res += 1
                time += 1

        except Exception as e:
            self.fail()

    def test_signal(self) -> None:
        batch_data = BatchData(TSDataType.INT32)
        try:
            batch_data.has_current()
        except ValueError:
            return


if __name__ == '__main__':
    unittest.main()
```

Please note that the `SignalBatchData` class is not present in your original Java code, so I did not translate it to Python.