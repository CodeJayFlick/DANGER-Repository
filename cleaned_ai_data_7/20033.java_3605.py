import io
from abc import ABCMeta, abstractmethod


class YggdrasilInputStream(metaclass=ABCMeta):
    def __init__(self, yggdrasil):
        self.yggdrasil = yggdrasil

    @abstractmethod
    def read_tag(self) -> int:
        pass

    # Primitives

    @abstractmethod
    def read_primitive(self, tag: int) -> object:
        pass

    # String

    @abstractmethod
    def read_string(self) -> str:
        pass

    # Array

    @abstractmethod
    def read_array_component_type(self) -> type:
        pass

    @abstractmethod
    def read_array_length(self) -> int:
        pass

    def read_array_contents(self, array: object):
        if isinstance(array, list):
            for i in range(len(array)):
                array[i] = self.read_primitive_(self.read_tag())
        else:
            length = self.read_array_length()
            component_type = self.read_array_component_type()
            for _ in range(length):
                Array.set(array, _, self.read_primitive_(self.read_tag()))

    # Enum

    @abstractmethod
    def read_enum_type(self) -> type:
        pass

    @abstractmethod
    def read_enum_id(self) -> str:
        pass

    def read_enum(self) -> object:
        enum_type = self.read_enum_type()
        id_ = self.read_enum_id()
        if issubclass(enum_type, Enum):
            return Yggdrasil.get_enum_constant(enum_type, id_)
        elif PseudoEnum in type.__mro__:
            obj = PseudoEnum.valueOf(enum_type, id_)
            if obj is not None:
                return obj
            raise StreamCorruptedException(f"Enum constant {id_} does not exist in {enum_type}")
        else:
            raise StreamCorruptedException(f"{enum_type} is not an enum type")

    # Class

    @abstractmethod
    def read_class(self) -> type:
        pass

    # Reference

    @abstractmethod
    def read_reference(self) -> int:
        pass

    # generic Object

    @abstractmethod
    def read_object_type(self) -> type:
        pass

    @abstractmethod
    def read_num_fields(self) -> int:
        pass

    @abstractmethod
    def read_field_id(self) -> str:
        pass

    def read_fields(self):
        fields = Fields(yggdrasil)
        num_fields = self.read_num_fields()
        for _ in range(num_fields):
            id_ = self.read_field_id()
            tag = self.read_tag()
            if isprimitive(tag):
                fields.put_primitive(id_, self.read_primitive(tag))
            else:
                fields.put_object(id_, self.read_object(tag))
        return fields

    def read_objects(self) -> list[object]:
        return []

    @abstractmethod
    def read_object(self, tag: int) -> object:
        pass


class Fields:
    def __init__(self, yggdrasil):
        self.yggdrasil = yggdrasil
        self.fields = {}

    def put_primitive(self, id_, value):
        self.fields[id_] = value

    def put_object(self, id_, value):
        self.fields[id_] = value

    def set_fields(self, obj):
        for key in self.fields:
            setattr(obj, key, self.fields[key])
