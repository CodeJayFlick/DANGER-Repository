class UnaryMeasurementSchema:
    def __init__(self):
        self.measurement_id = None
        self.type = None
        self.encoding = None
        self.props = {}

    def __init__(self, measurement_id: str, ts_data_type: int) -> None:
        this(measurement_id)
        self.ts_data_type = ts_data_type

    def this(self, measurement_id: str):
        self.measurement_id = measurement_id

    @staticmethod
    def deserialize_from(input_stream):
        if input_stream is not None and isinstance(input_stream, bytes):
            return UnaryMeasurementSchema()
        else:
            raise ValueError("Invalid Input Stream")

    @staticmethod
    def partial_deserialize_from(buffer: bytearray) -> 'UnaryMeasurementSchema':
        measurement_schema = UnaryMeasurementSchema()

        # Read the measurement ID from the buffer.
        measurement_schema.measurement_id = str(input_stream.read_string())

        # Read the type, encoding and compressor from the buffer.
        measurement_schema.type = input_stream.read_byte()
        measurement_schema.encoding = input_stream.read_byte()
        measurement_schema.compressor = input_stream.read_byte()

        return measurement_schema

    def get_measurement_id(self) -> str:
        return self.measurement_id

    def set_measurement_id(self, measurement_id: str):
        self.measurement_id = measurement_id

    @property
    def props(self):
        return self._props

    @props.setter
    def props(self, value):
        if isinstance(value, dict) and all(isinstance(k, str) for k in value.keys()):
            self._props = value
        else:
            raise ValueError("Invalid Props")

    def get_encoding_type(self) -> int:
        return self.encoding

    def set_encoding_type(self, encoding: int):
        self.encoding = encoding

    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, value):
        if isinstance(value, int):
            self._type = value
        else:
            raise ValueError("Invalid Type")

    def get_compressor(self) -> int:
        return self.compressor

    def set_compressor(self, compressor: int):
        self.compressor = compressor

    @staticmethod
    def serialize_to(output_stream, measurement_schema):
        if output_stream is not None and isinstance(output_stream, bytes):
            # Write the measurement ID to the buffer.
            output_stream.write_string(measurement_schema.measurement_id)

            # Write the type, encoding and compressor to the buffer.
            output_stream.write_byte(measurement_schema.type)
            output_stream.write_byte(measurement_schema.encoding)
            output_stream.write_byte(measurement_schema.compressor)

            if measurement_schema.props is not None:
                for key in measurement_schema.props.keys():
                    output_stream.write_string(key)
                    output_stream.write_string(measurement_schema.props[key])
        else:
            raise ValueError("Invalid Output Stream")

    @staticmethod
    def partial_serialize_to(output_stream, measurement_schema):
        # Write the measurement ID to the buffer.
        output_stream.write_string(measurement_schema.measurement_id)

        # Write the type and encoding to the buffer.
        output_stream.write_byte(measurement_schema.type)
        output_stream.write_byte(measurement_schema.encoding)

        return

    def __eq__(self, other):
        if self is None or other is None:
            return False
        elif isinstance(other, UnaryMeasurementSchema) and \
                self.measurement_id == other.measurement_id and \
                self.ts_data_type == other.ts_data_type and \
                self.encoding == other.encoding and \
                self.compressor == other.compressor:
            return True
        else:
            return False

    def __hash__(self):
        if isinstance(self, UnaryMeasurementSchema) and \
           hasattr(self, 'measurement_id') and \
           hasattr(self, 'ts_data_type'):
            return hash((self.measurement_id, self.ts_data_type))
        elif hasattr(self, '__dict__'):
            return hash(tuple(sorted(self.__dict__.items())))
        else:
            raise ValueError("Invalid Hash")

    def __lt__(self, other):
        if isinstance(other, UnaryMeasurementSchema) and \
           hasattr(self, 'measurement_id') and \
           hasattr(other, 'measurement_id'):
            return self.measurement_id < other.measurement_id
        elif hasattr(self, '__dict__') and \
             hasattr(other, '__dict__'):
            for key in sorted(list(self.__dict__.keys())):
                if key not in other.__dict__:
                    return True
            for key in sorted(list(other.__dict__.keys())):
                if key not in self.__dict__:
                    return False
        else:
            raise ValueError("Invalid Less Than")

    def __str__(self):
        if isinstance(self, UnaryMeasurementSchema) and \
           hasattr(self, 'measurement_id'):
            return f"UnaryMeasurementSchema(measurement_id='{self.measurement_id}')"
        elif hasattr(self, '__dict__'):
            return str({key: value for key, value in self.__dict__.items()})
        else:
            raise ValueError("Invalid String Representation")
