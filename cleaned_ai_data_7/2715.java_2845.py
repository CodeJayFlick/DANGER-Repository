class ID:
    def __new__(cls, obj):
        return cls(obj)

    def __init__(self, obj):
        self.obj = obj

    @property
    def object(self):
        return self.obj

    def __hash__(self):
        return hash(id(self.obj))

    def __eq__(self, other):
        if not isinstance(other, ID):
            return False
        that = other
        return self.obj == that.obj
