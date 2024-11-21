import abc

class AbstractImageBaseOffsetDataType(abc.ABC):
    def __init__(self, path, name, dtm):
        super().__init__()
        self.path = path
        self.name = name
        self.dtm = dtm

    @abc.abstractmethod
    def get_scalar_data_type(self):
        pass

    @staticmethod
    def generate_name(dt):
        return f"ImageBaseOffset{dt.length * 8}"

    @staticmethod
    def generate_mnemonic(dt):
        return f"ibo{dt.length * 8}"

    @staticmethod
    def generate_description(dt):
        return f"{dt.length * 8}-bit Image Base Offset"

    def get_description(self):
        dt = self.get_scalar_data_type()
        return self.generate_description(dt)

    def get_mnemonic(self, settings):
        dt = self.get_scalar_data_type()
        return self.generate_mnemonic(dt)

    @property
    def length(self):
        return self.get_scalar_data_type().length

    def get_representation(self, buf, settings, length):
        addr = self.get_value(buf, settings, length)
        if addr is None:
            return "NaP"
        return str(addr)

    def get_value(self, buf, settings, length):
        dt = self.get_scalar_data_type()
        image_base = buf.memory.program.image_base
        value = dt.get_value(buf, settings, length)
        if value and value.unsigned_value != 0:
            try:
                return image_base.add(value.unsigned_value)
            except AddressOutOfBoundsException as e:
                pass
        return None

    def is_encodable(self):
        return self.get_scalar_data_type().is_encodable()

    def encode_value(self, value, buf, settings, length):
        if not isinstance(value, tuple(Address)):
            raise DataTypeEncodeException("Requires Address", value, self)
        address_value = value
        image_base = buf.memory.program.image_base
        offset = 0
        try:
            offset = address_value.subtract(image_base).value
        except Exception as e:
            raise DataTypeEncodeException(value, self, e)

        scalar_offset = Scalar(address_value.size(), offset, False)
        dt = self.get_scalar_data_type()
        return dt.encode_value(scalar_offset, buf, settings, length)

    def encode_representation(self, repr, buf, settings, length):
        address = buf.memory.program.address_factory.get_address(repr)
        if not address:
            raise DataTypeEncodeException("Cannot parse address", repr, self)
        return self.encode_value(address, buf, settings, length)

    @property
    def value_class(self, settings=None):
        return Address

class DataType(abc.ABC):
    pass

class BuiltIn(DataType):
    pass

class CategoryPath:
    pass

class DataManagerInterface:
    pass

class MemBuffer:
    pass

class Program:
    pass

class Scalar:
    @property
    def length(self):
        pass

    @property
    def size(self):
        pass

    @property
    def unsigned_value(self):
        pass

class AddressOutOfBoundsException(Exception):
    pass

class DataTypeEncodeException(Exception):
    pass
