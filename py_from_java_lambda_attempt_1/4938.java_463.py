Here is the translation of the given Java code into equivalent Python:

```Python
class ObjectiveC1ProtocolMethodList:
    NAME = "objc_protocol_method_list"

    def __init__(self, state: 'ObjectiveC1State', reader, method_type):
        self._state = state
        self._index = reader.get_pointer_index()
        if not self._index:
            return

        self.method_count = reader.read_next_int()

        for _ in range(self.method_count):
            self.method_list.append(ObjectiveC1ProtocolMethod(state, reader, method_type))

    @property
    def method_count(self):
        return self.method_count

    @property
    def method_list(self):
        return self.method_list


class ObjectiveC1State:
    pass  # This class is not implemented in the given Java code. It's assumed to be a custom Python class.


def objective_c_1_protocol_method_list_to_generic_data_type(state: 'ObjectiveC1State') -> dict:
    data_type = {"name": "objc_protocol_method_list", "category_path": ObjectiveC1Constants.CATEGORY_PATH}
    return data_type


class StructureDataType(dict):
    def __init__(self, name, length):
        super().__init__()
        self.name = name
        self.length = length

    @property
    def category_path(self):
        return self.get("category_path")

    def add(self, key: str, value=None) -> None:
        if isinstance(value, StructureDataType):
            for k in value.keys():
                self[k] = {"type": "array", "length": len(list(value.values())), "value_type": type(next(iter(value.values())))}
        else:
            super().update({key: value})


class ArrayDataType(dict):
    def __init__(self, data_type, length, value_type=None) -> None:
        super().__init__()
        self.data_type = data_type
        self.length = length
        if value_type is not None:
            self.value_type = type(value_type)


def objective_c_1_protocol_method_list_to_data_type(self: 'ObjectiveC1ProtocolMethodList') -> dict:
    structure_data_type = {"name": f"objc_protocol_method_list_{self.method_count}_", "category_path": ObjectiveC1Constants.CATEGORY_PATH}
    if self.method_count > 0:
        data_type = self.method_list[0].to_data_type()
        array_data_type = {"type": "array", "length": self.method_count, "value_type": type(next(iter(self.method_list)))}
        structure_data_type.update({"method_ count": self.method_count})
        structure_data_type["method_list"] = array_data_type
    return structure_data_type


class ObjectiveC1ProtocolMethod:
    pass  # This class is not implemented in the given Java code. It's assumed to be a custom Python class.


def apply_to(self: 'ObjectiveC1ProtocolMethodList') -> None:
    if self._index == 0:
        return

    if self._state.been_applied.contains(self._index):
        return

    self._state.been_applied.add(self._index)

    address = self._state.program.get_address_factory().get_default_address_space().get_address(self._index)
    data_type = self.to_data_type()
    self._state.program.get_listing().clear_code_units(address, address.add(data_type["length"] - 1), False)
    self._state.program.get_listing().create_data(address, data_type)

    for method in self.method_list:
        if self._state.monitor.is_cancelled():
            break
        method.apply_to()
```

Note that this translation is not a direct conversion from Java to Python. It's more of an equivalent implementation based on the given code. Some classes and methods are assumed or simplified, as they were not provided in the original Java code.