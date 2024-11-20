class RichObjectCountDataType:
    def __init__(self, count):
        self.count = count

    @property
    def category_path(self):
        return "/PE"

    @category_path.setter
    def category_path(self, value):
        pass  # ignored

    @property
    def name(self):
        return "RichObjectCount"

    @name.setter
    def name(self, value):
        pass  # ignored

    def clone(self):
        return RichObjectCountDataType(self.count)

    def copy(self):
        return self.clone()

    def set_category_path(self, path):
        pass  # ignored

    def set_name(self, name):
        pass  # ignored

    def get_mnemonic(self, settings):
        return "xorddw"

    @property
    def length(self):
        return 4

    @length.setter
    def length(self, value):
        self._length = value

    def description(self):
        return None

    def get_value(self, buf, settings, length):
        return self.count

    def get_representation(self, buf, settings, length):
        return str(self.count)

    def is_equivalent(self, dt):
        if dt == self:
            return True
        elif dt is None:
            return False
        else:
            return isinstance(dt, RichObjectCountDataType)

# Example usage:
data_type = RichObjectCountDataType(5)
print(data_type.get_representation(None, None, 0))  # prints: 5
