import io.BytesIO as ByteArrayOutputStream
from typing import List

class RegularDataEncoderIntegerTest:
    ROW_NUM = 2000000
    out: ByteArrayOutputStream
    regular_data_encoder: object
    regular_data_decoder: object
    buffer: bytes

    def __init__(self):
        self.out = ByteArrayOutputStream()
        self.regular_data_encoder = RegularDataEncoder.IntRegularEncoder()
        self.regular_data_decoder = RegularDataDecoder.IntRegularDecoder()

    @staticmethod
    def get_missing_point_data(data_size, missing_point_interval) -> List[int]:
        original_row_num = data_size
        kong = 0

        for i in range(original_row_num):
            if i % missing_point_interval == 0:
                kong += 1

        row_num = original_row_num - kong

        data: List[int] = []
        j = 0
        for i in range(original_row_num):
            if i % missing_point_interval != 0:
                data.append(i)
        return data

    def write_data(self, data: List[int], length) -> None:
        for i in range(length):
            self.regular_data_encoder.encode(data[i], self.out)

        self.regular_data_encoder.flush()

    def should_read_and_write(self, data: List[int], length) -> None:
        self.out = ByteArrayOutputStream()
        self.write_data(data, length)
        page = self.out.getvalue().encode('utf-8')
        buffer = memoryview(page)
        i = 0
        while self.regular_data_decoder.has_next(buffer):
            assert (data[i] == int.from_bytes(self.regular_data_decoder.read_int(buffer).tobytes(), 'big'))
            i += 1

    def test_regular_encoding_without_missing_point(self) -> None:
        data: List[int] = list(range(ROW_NUM))
        self.should_read_and_write(data, ROW_NUM)

    def test_regular_with_one_percent_missing_points(self) -> None:
        data = self.get_missing_point_data(2000000, 80)
        self.should_read_and_write(data, ROW_NUM)

    def test_regular_with_five_percent_missing_points(self) -> None:
        data = self.get_missing_point_data(2000000, 20)
        self.should_read_and_write(data, ROW_NUM)

    def test_regular_with_ten_percent_missing_points(self) -> None:
        data = self.get_missing_point_data(2000000, 10)
        self.should_read_and_write(data, ROW_NUM)

    def test_regular_with_twenty_percent_missing_points(self) -> None:
        data = self.get_missing_point_data(2000000, 5)
        self.should_read_and_write(data, ROW_UM)

    def test_regular_with_low_missing_points1(self) -> None:
        data = self.get_missing_point_data(2000000, 1700)
        self.should_read_and_write(data, ROW_NUM)

    def test_regular_with_low_missing_points2(self) -> None:
        data = self.get_missing_point_data(2000000, 40000)
        self.should_read_and_write(data, ROW_NUM)

    def test_missing_points_data_size(self) -> None:
        original_data: List[int] = [1000, 1100, 1200, 1300, 1500, 2000]
        write_data(original_data, len(original_data))
        page = self.out.getvalue().encode('utf-8')
        buffer = memoryview(page)
        i = 0
        while self.regular_data_decoder.has_next(buffer):
            assert (original_data[i] == int.from_bytes(self.regular_data_decoder.read_int(buffer).tobytes(), 'big'))
            i += 1

    def test_missing_points_data_size(self) -> None:
        original_data: List[int] = [1000, 1100, 1200, 1300, 1500, 2000]
        write_data(original_data, len(original_data))
        page = self.out.getvalue().encode('utf-8')
        buffer = memoryview(page)
        i = 0
        while self.regular_data_decoder.has_next(buffer):
            assert (original_data[i] == int.from_bytes(self.regular_data_decoder.read_int(buffer).tobytes(), 'big'))
            i += 1

    def write_data(self, data: List[int], length) -> None:
        for i in range(length):
            self.regular_data_encoder.encode(data[i], self.out)

        self.regular_data_encoder.flush()

if __name__ == "__main__":
    test = RegularDataEncoderIntegerTest()
    test.test_regular_encoding_without_missing_point()
