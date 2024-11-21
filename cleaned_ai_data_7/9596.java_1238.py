class FieldLocation:
    MAX = (int(2**63)-1, int(2**31)-1, int(2**16)-1, int(2**8)-1)

    def __init__(self):
        self.index = 0
        self.field_num = 0
        self.row = 0
        self.col = 0

    def __init__(self, index=0, field_num=0, row=0, col=0):
        self.set_index(index)
        self.field_num = field_num
        self.row = row
        self.col = col

    @classmethod
    def from_element(cls, child):
        big_index_attribute = child.getAttribute("B")
        if big_index_attribute is not None:
            index = int(big_index_attribute)
        else:
            value = int(child.getAttribute("I"))
            index = value
        field_num = int(child.getAttribute("F"))
        row = int(child.getAttribute("R"))
        col = int(child.getAttribute("C"))

        return cls(index, field_num, row, col)

    def __copy__(self, loc):
        self.set_index(loc.index)
        self.field_num = loc.field_num
        self.row = loc.row
        self.col = loc.col

    @property
    def index(self):
        return self._index

    @index.setter
    def set_index(self, value):
        if isinstance(value, int) or isinstance(value, str):
            try:
                self._index = int(str(value))
            except ValueError as e:
                raise TypeError("Invalid integer: {}".format(e)) from None
        elif isinstance(value, bytes):
            self._index = int.from_bytes(value, 'big')
        else:
            raise TypeError("Index must be an integer or a string")

    @property
    def field_num(self):
        return self._field_num

    @field_num.setter
    def set_field_num(self, value):
        if isinstance(value, int) and 0 <= value < (2**31):
            self._field_num = value
        else:
            raise ValueError("Field number must be an integer between 0 and 2147483647")

    @property
    def row(self):
        return self._row

    @row.setter
    def set_row(self, value):
        if isinstance(value, int) and 0 <= value < (2**16):
            self._row = value
        else:
            raise ValueError("Row must be an integer between 0 and 65535")

    @property
    def col(self):
        return self._col

    @col.setter
    def set_col(self, value):
        if isinstance(value, int) and 0 <= value < (2**8):
            self._col = value
        else:
            raise ValueError("Column must be an integer between 0 and 255")

    def __eq__(self, other):
        return (
                self.index == other.index 
                and self.field_num == other.field_num 
                and self.row == other.row 
                and self.col == other.col)

    def __lt__(self, other):
        if not isinstance(other, FieldLocation):
            raise TypeError("Can only compare with another FieldLocation")
        return (
                self.index < other.index or
                (self.index == other.index) and 
                (self.field_num < other.field_num or 
                 (self.field_num == other.field_num) and 
                 ((self.row < other.row) or 
                  (self.row == other.row) and 
                  (self.col < other.col))))

    def __hash__(self):
        return hash((int(self.index), self.field_num, self.row, self.col))

    def to_element(self):
        element = Element("FieldLocation")
        if isinstance(self._index, int):
            element.setAttribute("B", str(self._index))
        else:
            element.setAttribute("I", str(int.from_bytes(self._index, 'big')))
        element.setAttribute("F", str(self.field_num))
        element.setAttribute("R", str(self.row))
        element.setAttribute("C", str(self.col))

    def __str__(self):
        return f"{self.index}, {self.field_num}, {self.row}, {self.col}"
