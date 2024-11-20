class DefaultSettingsPropertyMap:
    def __init__(self, name):
        self.prop_set = ObjectPropertySet(name)

    def add(self, addr, value):
        if not isinstance(value, Settings):
            raise TypeMismatchException("The property does not have Settings object values.")
        self.prop_set[addr] = value

    def get_settings(self, addr):
        return self.prop_set.get(addr) or None


class ObjectPropertySet(dict):
    pass


class Address:
    def __init__(self, key):
        self.key = key


class Settings:
    pass
