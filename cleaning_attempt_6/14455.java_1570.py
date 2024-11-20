class Message:
    def __init__(self):
        self.type = None
        self.content = ""

    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, value):
        self._type = value

    @property
    def content(self):
        return self._content

    @content.setter
    def content(self, value):
        self._content = value

    def __eq__(self, other):
        if not isinstance(other, Message):
            return False
        return (self.type == other.type and 
                self.content == other.content)

    def __hash__(self):
        return hash((self.type, self.content))
