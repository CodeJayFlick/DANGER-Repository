class FunctionRowObject:
    def __init__(self, function):
        self.function = function

    @property
    def function(self):
        return self.function

    def hash(self):
        return int(self.function.get_id())

    def equals(self, obj):
        if self is obj:
            return True
        if obj is None:
            return False
        if not isinstance(obj, FunctionRowObject):
            return False

        key = self.function.get_id()
        other = obj
        if key != other.function.get_id():
            return False
        return True

    @property
    def key(self):
        return self.function.get_id()

    def __lt__(self, o):
        return (int(self.function.get_id()) < int(o.function.get_id()))
