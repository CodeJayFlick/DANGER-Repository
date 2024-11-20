Here is the translation of the given Java code into equivalent Python:

```Python
class ObjectiveC2Protocol:
    def __init__(self, state, reader):
        self.state = state
        self.index = reader.get_pointer_index()
        
        if state.is_32bit():
            self.isa = reader.read_next_int() & 0xFFFFFFFF
            self.name = reader.read_ascii_string(reader.read_next_index())
        else:
            self.isa = reader.read_next_long()
            self.name = reader.read_ascii_string(reader.read_next_index())

        self.protocols = None if not read_protocols(reader) else ObjectiveC2ProtocolList(state, reader)
        self.instance_methods = None if not read_instance_methods(reader) else ObjectiveC2MethodList(state, reader, 'INSTANCE')
        self.class_methods = None if not read_class_methods(reader) else ObjectiveC2MethodList(state, reader, 'CLASS')
        self.optional_instance_methods = None if not read_optional_instance_methods(reader) else ObjectiveC2MethodList(state, reader, 'INSTANCE')
        self.optional_class_methods = None if not read_optional_class_methods(reader) else ObjectiveC2MethodList(state, reader, 'CLASS')
        self.instance_properties = None if not read_instance_properties(reader) else ObjectiveC2PropertyList(state, reader)

        if state.is_32bit():
            self.unknown0 = reader.read_next_int() & 0xFFFFFFFF
            self.unknown1 = reader.read_next_int() & 0xFFFFFFFF
        else:
            self.unknown0 = reader.read_next_long()
            self.unknown1 = reader.read_next_long()

    def get_isa(self):
        return self.isa

    def get_name(self):
        return self.name

    def get_protocols(self):
        return self.protocols

    def get_instance_methods(self):
        return self.instance_methods

    def get_class_methods(self):
        return self.class_methods

    def get_optional_instance_methods(self):
        return self.optional_instance_methods

    def get_optional_class_methods(self):
        return self.optional_class_methods

    def get_instance_properties(self):
        return self.instance_properties

    def get_unknown0(self):
        return self.unknown0

    def get_unknown1(self):
        return self.unknown1

    def get_index(self):
        return self.index


def read_protocols(reader):
    index = reader.read_next_index()
    if index != 0 and reader.is_valid_index(index):
        original_index = reader.get_pointer_index()
        reader.set_pointer_index(index)
        protocols = ObjectiveC2ProtocolList(state, reader) if state.is_32bit() else None
        reader.set_pointer_index(original_index)
        return True
    return False


def read_name(reader):
    index = reader.read_next_index()
    if index != 0 and reader.is_valid_index(index):
        name = reader.read_ascii_string(index)
        return True
    return False


def read_instance_methods(reader):
    index = reader.read_next_index()
    if index != 0 and reader.is_valid_index(index):
        original_index = reader.get_pointer_index()
        reader.set_pointer_index(index)
        instance_methods = ObjectiveC2MethodList(state, reader, 'INSTANCE')
        reader.set_pointer_index(original_index)
        return True
    return False


def read_class_methods(reader):
    index = reader.read_next_index()
    if index != 0 and reader.is_valid_index(index):
        original_index = reader.get_pointer_index()
        reader.set_pointer_index(index)
        class_methods = ObjectiveC2MethodList(state, reader, 'CLASS')
        reader.set_pointer_index(original_index)
        return True
    return False


def read_optional_instance_methods(reader):
    index = reader.read_next_index()
    if index != 0 and reader.is_valid_index(index):
        original_index = reader.get_pointer_index()
        reader.set_pointer_index(index)
        optional_instance_methods = ObjectiveC2MethodList(state, reader, 'INSTANCE')
        reader.set_pointer_index(original_index)
        return True
    return False


def read_optional_class_methods(reader):
    index = reader.read_next_index()
    if index != 0 and reader.is_valid_index(index):
        original_index = reader.get_pointer_index()
        reader.set_pointer_index(index)
        optional_class_methods = ObjectiveC2MethodList(state, reader, 'CLASS')
        reader.set_pointer_index(original_index)
        return True
    return False


def read_instance_properties(reader):
    index = reader.read_next_index()
    if index != 0 and reader.is_valid_index(index):
        original_index = reader.get_pointer_index()
        reader.set_pointer_index(index)
        instance_properties = ObjectiveC2PropertyList(state, reader)
        reader.set_pointer_index(original_index)
        return True
    return False


def to_data_type(self):
    struct = StructureDataType('protocol_t', 0)

    if self.state.is_32bit():
        struct.add(DWORD, 'isa', None)
    else:
        struct.add(QWORD, 'isa', None)

    struct.add(PointerDataType(STRING), self.state.pointer_size, 'name', None)
    struct.add(PointerDataType(ObjectiveC2ProtocolList.to_generic_data_type(self.state)), self.state.pointer_size, 'protocols', None)
    struct.add(PointerDataType(ObjectiveC2MethodList.to_generic_data_type()), self.state.pointer_size, 'instance_methods', None)
    struct.add(PointerDataType(ObjectiveC2MethodList.to_generic_data_type()), self.state.pointer_size, 'class_methods', None)
    struct.add(PointerDataType(ObjectiveC2MethodList.to_generic_data_type()), self.state.pointer_size, 'optional_instance_methods', None)
    struct.add(PointerDataType(ObjectiveC2MethodList.to_generic_data_type()), self.state.pointer_size, 'optional_class_methods', None)
    struct.add(PointerDataType(ObjectiveC2PropertyList.to_generic_data_type()), self.state.pointer_size, 'instance_properties', None)

    if self.state.is_32bit():
        struct.add(DWORD, 'unknown0', None)
        struct.add(DWORD, 'unknown1', None)
    else:
        struct.add(QWORD, 'unknown0', None)
        struct.add(QWORD, 'unknown1', None)

    return struct


def apply_to(self, namespace):
    address = ObjectiveC1Utilities.to_address(self.state.program, self.index)
    
    try:
        ObjectiveC1Utilities.apply_data(self.state.program, to_data_type(), address)
    except Exception as e:
        pass

    try:
        protocol_namespace = ObjectiveC1Utilities.create_namespace(self.state.program, ObjectiveC1Constants.NAMESPACE, 'protocol_t')
        ObjectiveC1Utilities.create_symbol(self.state.program, protocol_namespace, self.name, address)
    except Exception as e:
        pass
    
    if self.protocols is not None:
        self.protocols.apply_to(namespace)

    if self.instance_methods is not None:
        self.instance_methods.apply_to(namespace)

    if self.class_methods is not None:
        self.class_methods.apply_to(namespace)

    if self.optional_instance_methods is not None:
        self.optional_instance_methods.apply_to(namespace)

    if self.optional_class_methods is not None:
        self.optional_class_methods.apply_to(namespace)

    if self.instance_properties is not None:
        self.instance_properties.apply_to(namespace)
```

Please note that this translation assumes the existence of certain classes and functions (`ObjectiveC2ProtocolList`, `ObjectiveC2MethodList`, etc.) which are not defined in your original code.