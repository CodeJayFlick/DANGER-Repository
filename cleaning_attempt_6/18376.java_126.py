import datetime as dt
from dateutil import tz
from pytz import timezone
import io
import unittest
from unittest.mock import patch

class RegularDataEncoderLongTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.ROW_NUM = 0
        cls.out = io.BytesIO()
        cls.regular_data_encoder = None
        cls.regular_data_decoder = None
        cls.buffer = None

    def test(self):
        self.regular_data_encoder = RegularDataEncoder.LongRegularEncoder()
        self.regular_data_decoder = RegularDataDecoder.LongRegularDecoder()

    @unittest.skip("Test is not implemented")
    def test_regular_encoding_without_missing_point(self):
        dates = get_between_date_with_one_second("1980-01-01T01:00:00", "1980-01-28T01:00:00")

        date_format = dt.datetime.strptime("yyyy-MM-dd HH:mm:ss", "%Y-%m-%d %H:%M:%S").strftime

        self.ROW_NUM = len(dates)

        data = [date.timestamp() for i in range(len(dates))]
        should_read_and_write(data, self.ROW_NUM)

    @unittest.skip("Test is not implemented")
    def test_regular_with_one_percent_missing_points1(self):
        data = get_missing_point_data(get_between_date_with_one_second("1980-01-01T01:00:00", "1980-01-28T01:00:00"), 80)

        should_read_and_write(data, self.ROW_NUM)

    @unittest.skip("Test is not implemented")
    def test_regular_with_one_percent_missing_points2(self):
        data = get_missing_point_data(get_between_date_with_two_second("1980-01-01T01:00:00", "1980-01-28T01:00:00"), 80)

        should_read_and_write(data, self.ROW_NUM)

    @unittest.skip("Test is not implemented")
    def test_regular_with_five_percent_missing_points(self):
        data = get_missing_point_data(get_between_date_with_one_second("1980-01-01T01:00:00", "1980-01-28T01:00:00"), 20)

        should_read_and_write(data, self.ROW_NUM)

    @unittest.skip("Test is not implemented")
    def test_regular_with_ten_percent_missing_points(self):
        data = get_missing_point_data(get_between_date_with_one_second("1980-01-01T01:00:00", "1980-01-28T01:00:00"), 10)

        should_read_and_write(data, self.ROW_NUM)

    @unittest.skip("Test is not implemented")
    def test_regular_with_twenty_percent_missing_points(self):
        data = get_missing_point_data(get_between_date_with_one_second("1980-01-01T01:00:00", "1980-01-28T01:00:00"), 5)

        should_read_and_write(data, self.ROW_NUM)

    @unittest.skip("Test is not implemented")
    def test_regular_with_low_missing_points1(self):
        data = get_missing_point_data(get_between_date_with_one_second("1980-01-01T01:00:00", "1980-01-28T01:00:00"), 1700)

        should_read_and_write(data, self.ROW_NUM)

    @unittest.skip("Test is not implemented")
    def test_regular_with_low_missing_points2(self):
        data = get_missing_point_data(get_between_date_with_one_second("1980-01-01T01:00:00", "1980-01-28T01:00:00"), 40000)

        should_read_and_write(data, self.ROW_NUM)

    @unittest.skip("Test is not implemented")
    def test_missing_points_data_size(self):
        original_data = [1000, 1100, 1200, 1300, 1500, 2000]
        out = io.BytesIO()
        write_data(original_data, len(original_data))
        page = out.getvalue()
        buffer = memoryview(page)
        i = 0
        while self.regular_data_decoder.has_next(buffer):
            assertEquals(original_data[i++], self.regular_data_decoder.read_long(buffer))

    def get_missing_point_data(self, original_data, missing_point_interval):
        dates = original_data

        date_format = dt.datetime.strptime("yyyy-MM-dd HH:mm:ss", "%Y-%m-%d %H:%M:%S").strftime

        kong = 0
        for i in range(len(dates)):
            if i % missing_point_interval == 0:
                kong += 1

        self.ROW_NUM = len(dates) - kong

        data = [date.timestamp() for i in range(kong)]
        return data

    def get_between_date_with_one_second(self, start, end):
        tz.set_default_timezone(tz.gettz('GMT+8'))
        date_format = dt.datetime.strptime("yyyy-MM-dd HH:mm:ss", "%Y-%m-%d %H:%M:%S").strftime
        dates = []
        start_date = dt.datetime.strptime(start, "%Y-%m-%d %H:%M:%S")
        end_date = dt.datetime.strptime(end, "%Y-%m-%d %H:%M:%S")

        distance = (end_date - start_date).total_seconds()
        if distance < 1:
            return dates
        for d in dt.timedelta(seconds=1) + iter((start_date,)):
            while d.total_seconds() <= end_date.timestamp():
                dates.append(d.strftime(date_format))
                yield from iter([d])
            break

    def get_between_date_with_two_second(self, start, end):
        tz.set_default_timezone(tz.gettz('GMT+8'))
        date_format = dt.datetime.strptime("yyyy-MM-dd HH:mm:ss", "%Y-%m-%d %H:%M:%S").strftime
        dates = []
        start_date = dt.datetime.strptime(start, "%Y-%m-%d %H:%M:%S")
        end_date = dt.datetime.strptime(end, "%Y-%m-%d %H:%M:%S")

        distance = (end_date - start_date).total_seconds()
        if distance < 1:
            return dates
        for d in dt.timedelta(seconds=2) + iter((start_date,)):
            while d.total_seconds() <= end_date.timestamp():
                dates.append(d.strftime(date_format))
                yield from iter([d])
            break

    def write_data(self, data, length):
        self.regular_data_encoder.encode(data[0], self.out)
        for i in range(1, len(data)):
            self.regular_data_encoder.encode(data[i], self.out)

    def should_read_and_write(self, data, length) -> None:
        out = io.BytesIO()
        write_data(data, length)
        page = out.getvalue()
        buffer = memoryview(page)
        i = 0
        while self.regular_data_decoder.has_next(buffer):
            assertEquals(data[i++], self.regular_data_decoder.read_long(buffer))

if __name__ == '__main__':
    unittest.main()

