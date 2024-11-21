class TSEncodingBuilder:
    def __init__(self):
        self.conf = TSFileDescriptor().get_config()

    @staticmethod
    def get_encoding_builder(type: 'TSEncoding') -> 'TSEncodingBuilder':
        if type == TSEncoding.PLAIN:
            return Plain()
        elif type == TSEncoding.RLE:
            return Rle()
        # Add more types as needed

    abstract def get_encoder(self, type: TSDataType) -> Encoder
    abstract def init_from_props(self, props: dict)

class Plain(TSEncodingBuilder):
    max_string_length = 0

    def __init__(self):
        super().__init__()

    def get_encoder(self, type: TSDataType) -> Encoder:
        if type in [TSDataType.INT32, TSDataType.BOOLEAN]:
            return IntRleEncoder()
        elif type in [TSDataType.FLOAT, TSDataType.DOUBLE]:
            return FloatEncoder(TSEncoding.RLE, type, self.max_string_length)
        else:
            raise UnSupportedDataTypeException("PLAIN doesn't support data type: " + str(type))

    def init_from_props(self, props: dict):
        if 'max_string_length' in props and isinstance(props['max_string_length'], int) and 0 <= props['max_string_length']:
            self.max_string_length = props['max_string_length']
        else:
            logger.warn("Cannot set max string length to negative value. Using default value.")

class Rle(TSEncodingBuilder):
    max_point_number = TSFileDescriptor().get_float_precision()

    def __init__(self):
        super().__init__()

    def get_encoder(self, type: TSDataType) -> Encoder:
        if type in [TSDataType.INT32, TSDataType.BOOLEAN]:
            return IntRleEncoder()
        elif type in [TSDataType.FLOAT, TSDataType.DOUBLE]:
            return FloatEncoder(TSEncoding.RLE, type, self.max_point_number)
        else:
            raise UnSupportedDataTypeException("RLE doesn't support data type: " + str(type))

    def init_from_props(self, props: dict):
        if 'max_point_number' in props and isinstance(props['max_point_number'], int) and 0 <= props['max_point_number']:
            self.max_point_number = props['max_point_number']
        else:
            logger.warn("The format of max point number {} is not correct. Using default float precision.".format(props.get('max_point_number')))

    def __str__(self):
        return str(self.max_point_number)
