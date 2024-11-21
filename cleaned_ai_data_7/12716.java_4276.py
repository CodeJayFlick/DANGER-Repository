class DefaultObjectPropertyMap:
    def __init__(self, name: str, object_class):
        self.prop_set = SaveableObjectPropertySet(name, object_class)

    def add(self, addr: int, value) -> None:
        if not isinstance(value, Saveable):
            raise TypeError("Value must be of type Saveable")
        self.prop_set.put_object(addr, value)

    def get_object(self, addr: int) -> any:
        return self.prop_set.get_object(addr)

    def get_object_class(self) -> type:
        return self.prop_set.get_object_class()
