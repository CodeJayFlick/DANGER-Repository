import logging
from io import ByteArrayOutputStream
from java.nio.ByteBuffer import wrap

class GorillaDecoderV1Test:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.delta = 0.0000001
        self.float_max_point_value = 10000
        self.double_max_point_value = 1000000000000000
        self.float_list = []
        self.double_list = []

    def setUp(self):
        for i in range(11):
            hybrid_count = 50
            hybrid_num = 2000
            for j in range(hybrid_count):
                self.float_list.append((hybrid_num / float_max_point_value))
            for k in range(hybrid_count):
                self.float_list.append((hybrid_num / float_max_point_value) + (k * 3))
        hybrid_count += 2

        for i in range(11):
            hybrid_count_double = 50
            hybrid_start_double = 2000
            for j in range(hybrid_count_double):
                self.double_list.append((hybrid_start_double / double_max_point_value))
            for k in range(hybrid_count_double):
                self.double_list.append((hybrid_start_double / double_max_point_value) + (k * 3))

    def tearDown(self):
        pass

    def test_negative_number(self):
        encoder = SinglePrecisionEncoderV1()
        baos = ByteArrayOutputStream()
        value = -7.101
        for i in range(2):
            encoder.encode(value, baos)
            buffer = wrap(baos.toByteArray())
            decoder = SinglePrecisionDecoderV1()
            while decoder.hasNext(buffer):
                self.assertAlmostEqual(decoder.readFloat(buffer), value, delta)

    def test_zero_number(self):
        encoder = DoublePrecisionEncoderV1()
        baos = ByteArrayOutputStream()
        value = 0
        for i in range(4):
            encoder.encode(value, baos)
        buffer = wrap(baos.toByteArray())
        decoder = DoublePrecisionDecoderV1()
        while decoder.hasNext(buffer):
            self.assertAlmostEqual(decoder.readDouble(buffer), value, delta)

    def test_float_repeat(self):
        for _ in range(10):
            self.test_float_length(self.float_list, False, 1)
            self.test_double_length(self.double_list, False, 1)

    def test_double_repeat(self):
        for _ in range(10):
            self.test_float_length(self.float_list, False, 1)
            self.test_double_length(self.double_list, False, 1)

    def test_float(self):
        encoder = SinglePrecisionEncoderV1()
        baos = ByteArrayOutputStream()
        value = 7.101
        for i in range(10000):
            encoder.encode(value + (i * 2), baos)
        buffer = wrap(baos.toByteArray())
        decoder = SinglePrecisionDecoderV1()
        while decoder.hasNext(buffer):
            self.assertAlmostEqual(decoder.readFloat(buffer), value + (decoder.position() // 4) * 2, delta)

    def test_double(self):
        encoder = DoublePrecisionEncoderV1()
        baos = ByteArrayOutputStream()
        value = 7.101
        for i in range(1000):
            encoder.encode(value + (i * 2), baos)
        buffer = wrap(baos.toByteArray())
        decoder = DoublePrecisionDecoderV1()
        while decoder.hasNext(buffer):
            self.assertAlmostEqual(decoder.readDouble(buffer), value + (decoder.position() // 8) * 2, delta)

    def test_float_length(self, value_list, is_debug, repeat_count):
        encoder = SinglePrecisionEncoderV1()
        baos = ByteArrayOutputStream()
        for i in range(repeat_count):
            for value in value_list:
                encoder.encode(value, baos)
            encoder.flush(baos)
        buffer = wrap(baos.toByteArray())
        decoder = SinglePrecisionDecoderV1()
        for _ in range(repeat_count):
            for value in value_list:
                if decoder.hasNext(buffer):
                    self.assertAlmostEqual(decoder.readFloat(buffer), value, delta)

    def test_double_length(self, value_list, is_debug, repeat_count):
        encoder = DoublePrecisionEncoderV1()
        baos = ByteArrayOutputStream()
        for i in range(repeat_count):
            for value in value_list:
                encoder.encode(value, baos)
            encoder.flush(baos)
        buffer = wrap(baos.toByteArray())
        decoder = DoublePrecisionDecoderV1()
        for _ in range(repeat_count):
            for value in value_list:
                if decoder.hasNext(buffer):
                    self.assertAlmostEqual(decoder.readDouble(buffer), value, delta)

if __name__ == "__main__":
    test = GorillaDecoderV1Test()
    test.setUp()
