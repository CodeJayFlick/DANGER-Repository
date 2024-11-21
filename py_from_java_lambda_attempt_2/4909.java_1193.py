Here is the translation of the given Java code into equivalent Python code:

```Python
class ObjectiveC2_Category:
    NAME = "category_t"

    def __init__(self, state: 'ObjectiveC2_State', reader):
        self._state = state
        self._index = reader.get_pointer_index()

        self.read_name(reader)
        self.read_class(reader)

        if cls is not None and cls.get_isa() is not None:
            self.read_instance_methods(reader)
            self.read_class_methods(reader)
            self.read_protocols(reader)
            self.read_instance_properties(reader)

    @property
    def index(self):
        return self._index

    @property
    def name(self):
        return self.name_

    @name.setter
    def name(self, value: str):
        self.name_ = value

    @property
    def cls(self):
        return self.cls_

    @cls.setter
    def cls(self, value: 'ObjectiveC2_Class'):
        self.cls_ = value

    @property
    def instance_methods(self):
        return self.instance_methods_

    @instance_methods.setter
    def instance_methods(self, value: 'ObjectiveC2_MethodList'):
        self.instance_methods_ = value

    @property
    def class_methods(self):
        return self.class_methods_

    @class_methods.setter
    def class_methods(self, value: 'ObjectiveC2_MethodList'):
        self.class_methods_ = value

    @property
    def protocols(self):
        return self.protocols_

    @protocols.setter
    def protocols(self, value: 'ObjectiveC2_ProtocolList'):
        self.protocols_ = value

    @property
    def instance_properties(self):
        return self.instance_properties_

    @instance_properties.setter
    def instance_properties(self, value: 'ObjectiveC2_PropertyList'):
        self.instance_properties_ = value

    def read_name(self, reader) -> None:
        index = ObjectiveC1Utilities.read_next_index(reader, state.is32bit)
        if index != 0 and reader.is_valid_index(index):
            name = reader.read_ascii_string(index)
            self.name = name

    def read_class(self, reader) -> None:
        index = ObjectiveC1Utilities.read_next_index(reader, state.is32bit)

        if state.class_index_map.get(index):
            cls_ = state.class_index_map[index]
            return

        if index != 0 and reader.is_valid_index(index):
            original_index = reader.get_pointer_index()
            reader.set_pointer_index(index)
            cls_ = ObjectiveC2_Class(state, reader)
            reader.set_pointer_index(original_index)

    def read_instance_methods(self, reader) -> None:
        index = ObjectiveC1Utilities.read_next_index(reader, state.is32bit)
        if index != 0 and reader.is_valid_index(index):
            original_index = reader.get_pointer_index()
            reader.set_pointer_index(index)
            instance_methods_ = ObjectiveC2_MethodList(state, reader, ObjectiveC_MethodType.INSTANCE)
            reader.set_pointer_index(original_index)

    def read_class_methods(self, reader) -> None:
        index = ObjectiveC1Utilities.read_next_index(reader, state.is32bit)
        if index != 0 and reader.is_valid_index(index):
            original_index = reader.get_pointer_index()
            reader.set_pointer_index(index)
            class_methods_ = ObjectiveC2_MethodList(state, reader, ObjectiveC_MethodType.CLASS)
            reader.set_pointer_index(original_index)

    def read_protocols(self, reader) -> None:
        index = ObjectiveC1Utilities.read_next_index(reader, state.is32bit)
        if index != 0 and reader.is_valid_index(index):
            original_index = reader.get_pointer_index()
            reader.set_pointer_index(index)
            protocols_ = ObjectiveC2_ProtocolList(state, reader)
            reader.set_pointer_index(original_index)

    def read_instance_properties(self, reader) -> None:
        index = ObjectiveC1Utilities.read_next_index(reader, state.is32bit)
        if index != 0 and reader.is_valid_index(index):
            original_index = reader.get_pointer_index()
            reader.set_pointer_index(index)
            instance_properties_ = ObjectiveC2_PropertyList(state, reader)
            reader.set_pointer_index(original_index)

    def to_data_type(self) -> 'DataType':
        buffer = StringBuffer()
        buffer.append(NAME)

        if cls is None:
            buffer.append("<no_class>")
        else:
            buffer.append(cls.to_data_type())

        struct = StructureDataType(buffer.toString(), 0)

        struct.add(PointerDataType(STRING), state.pointer_size, "name", None)
        if cls is None:
            struct.add(PointerDataType VOID, state.pointer_size, "cls", None)
        else:
            struct.add(PointerDataType(cls.to_data_type()), state.pointer_size, "cls", None)

        struct.add(PointerDataType(ObjectiveC2_MethodList.to_generic_data_type()), state.pointer_size, "instance_methods", None)
        struct.add(PointerDataType(ObjectiveC2_MethodList.to-generic-data-type()), state.pointer_size, "class_methods", None)
        struct.add(PointerDataType(ObjectiveC2_ProtocolList.to-generic-data-type(state)), state.pointer_size, "protocols", None)
        struct.add(PointerDataType(ObjectiveC2_PropertyList.to-generic-data-type()), state.pointer_size, "instance_properties", None)

        struct.set_category_path(ObjectiveC2_Constants.CATEGORY_PATH)
        return struct

    def apply_to(self) -> None:
        address = Objective1Utilities.to_address(state.program, self.index)

        try:
            Objective1Utilities.apply_data(state.program, self.to_data_type(), address)
        except Exception as e:
            pass

        try:
            namespace = Objective1Utilities.create_namespace(state.program, Objective1_Constants.NAMESPACE, Objective2_Category.NAME)
            Objective1Utilities.create_symbol(state.program, namespace, self.name, address)
        except Exception as e:
            pass

        string = None
        try:
            if cls is not None:
                string = f"{cls.get_data().get_name()}_{self.name}_"
            else:
                string = self.name
        except Exception as e:
            string = self.name

        namespace = Objective1Utilities.create_namespace(state.program, Objective1_Constants.NAMESPACE, "Categories", string)

        if cls is not None:
            cls.apply_to()
        if instance_methods is not None:
            instance_methods.apply_to(namespace)
        if class_methods is not None:
            class_methods.apply_to(namespace)
        if protocols is not None:
            protocols.apply_to(namespace)
        if instance_properties is not None:
            instance_properties.apply_to(namespace)

class ObjectiveC2_State: pass

class Objective1Utilities: pass
```

Please note that this translation may require some manual adjustments to the code, as Python does not support direct equivalent of Java's `package`, `import` statements or `throws Exception`.