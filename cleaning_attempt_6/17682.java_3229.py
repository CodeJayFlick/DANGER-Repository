class EncodingInferenceUtils:
    def __init__(self):
        pass  # util class

    @staticmethod
    def get_default_encoding(data_type: str) -> str:
        conf = IoTDBConfig()
        if data_type == 'BOOLEAN':
            return conf.get_default_boolean_encoding()
        elif data_type == 'INT32':
            return conf.get_default_int32_encoding()
        elif data_type == 'INT64':
            return conf.get_default_int64_encoding()
        elif data_type == 'FLOAT':
            return conf.get_default_float_encoding()
        elif data_type == 'DOUBLE':
            return conf.get_default_double_encoding()
        elif data_type == 'TEXT':
            return conf.get_default_text_encoding()
        else:
            raise UnSupportedDataTypeException(f"Data type {data_type} is not supported.")
