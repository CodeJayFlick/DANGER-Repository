class TargetAttributeType:
    def __init__(self):
        self.name = ""
        self.type = type(None)
        self.required = False
        self.fixed = False
        self.hidden = False

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        if not isinstance(value, str):
            raise TypeError("Name must be a string")
        self._name = value

    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, value):
        if not isinstance(value, type):
            raise TypeError("Type must be a class or subclass of object")
        self._type = value

    @property
    def required(self):
        return self._required

    @required.setter
    def required(self, value):
        if not isinstance(value, bool):
            raise TypeError("Required must be a boolean")
        self._required = value

    @property
    def fixed(self):
        return self._fixed

    @fixed.setter
    def fixed(self, value):
        if not isinstance(value, bool):
            raise TypeError("Fixed must be a boolean")
        self._fixed = value

    @property
    def hidden(self):
        return self._hidden

    @hidden.setter
    def hidden(self, value):
        if not isinstance(value, bool):
            raise TypeError("Hidden must be a boolean")
        self._hidden = value
