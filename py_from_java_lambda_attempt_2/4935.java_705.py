Here is the translation of the given Java code into Python:

```Python
import io


class ObjectiveC1Protocol:
    NAME = "objc_protocol"
    SIZEOF = 20

    def __init__(self, state: 'ObjectiveC1State', reader):
        self._state = state
        self._index = reader.get_pointer_index()

        self.isa = reader.read_next_int()
        self.name = ObjectiveC1Utilities.dereference_ascii_string(reader, state.is_32bit)
        self.protocol_list = ObjectiveC1ProtocolList(state, reader.clone(reader.read_next_int()))
        self.instance_methods = ObjectiveC1ProtocolMethodList(state, reader.clone(reader.read_next_int()), 'INSTANCE')
        self.class_methods = ObjectiveC1ProtocolMethodList(state, reader.clone(reader.read_next_int()), 'CLASS')

    @property
    def isa(self):
        return self.isa

    @property
    def name(self):
        return self.name

    @property
    def protocol_list(self):
        return self.protocol_list

    @property
    def instance_methods(self):
        return self.instance_methods

    @property
    def class_methods(self):
        return self.class_methods

    def to_data_type(self) -> 'DataType':
        struct = DataType(NAME, 0)
        struct.set_category_path(ObjectiveC1Constants.CATEGORY_PATH)
        struct.add(DWORD, "isa", None)
        struct.add(ASCIIPointerType(state.pointer_size), "name", None)
        struct.add(ObjectiveC1ProtocolList.to_generic_data_type(state).get_pointer_type(state.pointer_size), "protocol_list", None)
        struct.add(ObjectiveC1ProtocolMethodList.to_generic_data_type(state).get_pointer_type(state.pointer_size), "instance_methods", None)
        struct.add(ObjectiveC1ProtocolMethodList.to_generic_data_type(state).get_pointer_type(state.pointer_size), "class_methods", None)
        return struct

    def apply_to(self) -> None:
        if state.been_applied.contains(index):
            return
        state.been_applied.add(index)

        address = state.program.get_address_factory().default_address_space().address(index)
        data_type = self.to_data_type()
        state.program.listing.clear_code_units(address, address + (data_type.length - 1), False)
        state.program.listing.create_data(address, data_type)

        self.protocol_list.apply_to()
        self.instance_methods.apply_to()
        self.class_methods.apply_to()


class ObjectiveC1State:
    def __init__(self):
        pass

    @property
    def been_applied(self) -> 'set':
        return set()

    @property
    def program(self) -> 'Program':
        return Program()

    @property
    def is_32bit(self) -> bool:
        return False


class ObjectiveC1ProtocolList:
    def __init__(self, state: 'ObjectiveC1State', reader):
        pass

    @staticmethod
    def to_generic_data_type(state: 'ObjectiveC1State') -> 'DataType':
        pass

    def apply_to(self) -> None:
        pass


class ObjectiveC1ProtocolMethodList:
    def __init__(self, state: 'ObjectiveC1State', reader, method_type):
        pass

    @staticmethod
    def to_generic_data_type(state: 'ObjectiveC1State') -> 'DataType':
        pass

    def apply_to(self) -> None:
        pass


class Program:
    def get_address_factory(self) -> 'AddressFactory':
        return AddressFactory()

    def listing(self) -> 'Listing':
        return Listing()


class AddressFactory:
    @staticmethod
    def default_address_space() -> 'AddressSpace':
        return AddressSpace()


class AddressSpace:
    def address(self, index: int) -> 'Address':
        pass


class DataType:
    def __init__(self, name: str, length: int):
        self.name = name
        self.length = length

    @property
    def category_path(self) -> str:
        return ""

    def add(self, data_type: 'DataType', field_name: str, null_value: bool) -> None:
        pass


class Listing:
    def clear_code_units(self, address: 'Address', end_address: 'Address', truncate_tail: bool) -> None:
        pass

    def create_data(self, address: 'Address', data_type: 'DataType') -> None:
        pass
```

Please note that this is a direct translation of the given Java code into Python. The original code seems to be part of a larger program and some classes like `ObjectiveC1State`, `ObjectiveC1ProtocolList`, `ObjectiveC1ProtocolMethodList`, `Program`, `AddressFactory`, `AddressSpace` are not fully implemented in this translation as they were missing their implementations in the given Java code.