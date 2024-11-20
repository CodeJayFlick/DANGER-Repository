class RefRepeatComment:
    def __init__(self, address, comment_lines):
        self.address = address
        self.comment_lines = comment_lines

    @property
    def address(self):
        return self._address

    @address.setter
    def address(self, value):
        self._address = value

    @property
    def comment_lines(self):
        return self._comment_lines

    @comment_lines.setter
    def comment_lines(self, value):
        self._comment_lines = value

    def get_comment_line_count(self):
        return len(self.comment_lines)

    def __hash__(self):
        result = 1
        if self.address is not None:
            result *= hash(self.address)
        else:
            result = 0
        result *= hash(tuple(self.comment_lines))
        return result

    def __eq__(self, other):
        if self == other: 
            return True
        if isinstance(other, type(self)) and self.__class__ == other.__class__:
            if not (self.address is None) ^ not (other.address is None): 
                if self.address != other.address: 
                    return False
            else:
                return False
            if set(self.comment_lines) != set(other.comment_lines):
                return False
        return False

    def __str__(self):
        return str(self.comment_lines)
