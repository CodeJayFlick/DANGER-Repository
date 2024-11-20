class Decoder:
    ERROR_MSG = "Decoder not found: %s , DataType is : %s"

    def __init__(self, type):
        self.type = type

    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, value):
        self._type = value

    @staticmethod
    def get_decoder_by_type(encoding, data_type):
        if encoding == "PLAIN":
            return PlainDecoder()
        elif encoding == "RLE":
            if data_type in [TSDataType.BOOLEAN, TSDataType.INT32]:
                return IntRleDecoder()
            elif data_type in [TSDataType.INT64, TSDataType.VECTOR]:
                return LongRleDecoder()
            elif data_type in [TSDataType.FLOAT, TSDataType.DOUBLE]:
                return FloatDecoder(encoding, data_type)
        elif encoding == "TS_2DIFF":
            if data_type == TSDataType.INT32:
                return DeltaBinaryDecoder.IntDeltaDecoder()
            elif data_type in [TSDataType.INT64, TSDataType.VECTOR]:
                return DeltaBinaryDecoder.LongDeltaDecoder()
            elif data_type in [TSDataType.FLOAT, TSDataType.DOUBLE]:
                return FloatDecoder(encoding, data_type)
        elif encoding == "GORILLA_V1":
            if data_type == TSDataType.FLOAT:
                return SinglePrecisionDecoderV1()
            elif data_type == TSDataType.DOUBLE:
                return DoublePrecisionDecoderV1()
        elif encoding == "REGULAR":
            if data_type == TSDataType.INT32:
                return RegularDataDecoder.IntRegularDecoder()
            elif data_type in [TSDataType.INT64, TSDataType.VECTOR]:
                return RegularDataDecoder.LongRegularDecoder()
        elif encoding == "GORILLA":
            if data_type == TSDataType.FLOAT:
                return SinglePrecisionDecoderV2()
            elif data_type == TSDataType.DOUBLE:
                return DoublePrecisionDecoderV2()
            elif data_type in [TSDataType.INT32, TSDataType.VECTOR]:
                return LongGorillaDecoder()
        elif encoding == "DICTIONARY":
            return DictionaryDecoder()

    def read_int(self, buffer):
        raise TsFileDecodingException("Method readInt is not supported by Decoder")

    def read_boolean(self, buffer):
        raise TsFileDecodingException("Method readBoolean is not supported by Decoder")

    def read_short(self, buffer):
        raise TsFileDecodingException("Method readShort is not supported by Decoder")

    def read_long(self, buffer):
        raise TsFileDecodingException("Method readLong is not supported by Decoder")

    def read_float(self, buffer):
        raise TsFileDecodingException("Method readFloat is not supported by Decoder")

    def read_double(self, buffer):
        raise TsFileDecodingException("Method readDouble is not supported by Decoder")

    def read_binary(self, buffer):
        raise TsFileDecodingException("Method readBinary is not supported by Decoder")

    def read_big_decimal(self, buffer):
        raise TsFileDecodingException("Method readBigDecimal is not supported by Decoder")

    def __abstract_has_next__(self, buffer):
        pass

    def reset(self):
        pass
