class ObjectiveC1_MetaClass:
    def __init__(self, state, reader):
        self._state = state
        self._index = reader.get_pointer_index()

        self.isa = ObjectiveC1_Utilities.dereference_ascii_string(reader, state.is32bit)
        self.super_class = ObjectiveC1_Utilities.dereference_ascii_string(reader, state.is32bit)
        self.name = ObjectiveC1_Utilities.dereference_ascii_string(reader, state.is32bit)

        self.version = reader.read_next_int()
        self.info = reader.read_next_int()
        self.instance_size = reader.read_next_int()

        self.variable_list = ObjectiveC1_InstanceVariableList(state, reader.clone(reader.read_next_int()))
        self.method_list = ObjectiveC1_MethodList(state, reader.clone(reader.read_next_int()), 'INSTANCE')
        self.cache = reader.read_next_int()
        self.protocols = ObjectiveC1_ProtocolList(state, reader.clone(reader.read_next_int()))

    def get_isa(self):
        return self.isa

    def get_super_class(self):
        return self.super_class

    def get_name(self):
        return self.name

    def get_version(self):
        return self.version

    def get_info(self):
        return self.info

    def get_instance_size(self):
        return self.instance_size

    def get_variable_list(self):
        return self.variable_list

    def get_method_list(self):
        return self.method_list

    def get_cache(self):
        return self.cache

    def get_protocols(self):
        return self.protocols


class ObjectiveC1_MetaClassConverter:
    @staticmethod
    def to_data_type(objc_meta_class, state):
        name = "objc_metaclass"
        struct = {"name": name}
        struct["category_path"] = ObjectiveC1_Constants.CATEGORY_PATH

        for field in ["isa", "super_class", "name"]:
            struct[field] = PointerDataType.get_pointer(ASCII, state.pointer_size)

        for field in ["version", "info", "instance_size", "cache", "unknown0", "unknown1"]:
            struct[field] = DWORD

        if objc_meta_class.variable_list:
            struct["instance_vars"] = ObjectiveC1_InstanceVariableList.to_generic_data_type(state)
        else:
            struct["instance_vars"] = None

        if objc_meta_class.method_list:
            struct["method_lists"] = ObjectiveC1_MethodList.to_generic_data_type(objc_meta_class._state, state)
        else:
            struct["method_lists"] = None

        return StructureDataType(struct)


class ObjectiveC1_MetaClassApplicator:
    @staticmethod
    def apply_to(objc_meta_class):
        if objc_meta_class._state.been_applied.contains(objc_meta_class._index):
            return

        objc_meta_class._state.been_applied.add(objc_meta_class._index)

        address = objc_meta_class._state.program.get_address_factory().get_default_address_space().get_address(objc_meta_class._index)
        data_type = ObjectiveC1_MetaClassConverter.to_data_type(objc_meta_class, objc_meta_class._state)
        objc_meta_class._state.program.get_listing().clear_code_units(address, address.add(data_type.length - 1), False)
        objc_meta_class._state.program.get_listing().create_data(address, data_type)

        namespace = ObjectiveC1_Utilities.create_namespace(objc_meta_class._state.program, ObjectiveC1_Constants.NAMESPACE, "Meta-classes", objc_meta_class.name)

        if objc_meta_class.variable_list:
            objc_meta_class.variable_list.apply_to()
        if objc_meta_class.method_list:
            objc_meta_class.method_list.apply_to(namespace)
        if objc_meta_class.protocols:
            objc_meta_class.protocols.apply_to()

