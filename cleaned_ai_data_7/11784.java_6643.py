class StarQuality:
    def __init__(self, location):
        self.location = location
        self.id = None
        self.size = 0

    # don't need these complicated constructors right now
#     def __init__(self, id, size):
#         self.id = id
#         self.size = size

#     def __init__(self, sq):
#         self.id = sq.id
#         self.size = sq.size

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, value):
        if not isinstance(value, ConstTpl):  # assuming ConstTpl is a class in Python
            raise ValueError("Invalid ID")
        self._id = value

#     def getId(self):
#         return self.id

    @property
    def size(self):
        return self._size

    @size.setter
    def size(self, value):
        if not isinstance(value, int):  # assuming you want the size to be an integer in Python
            raise ValueError("Invalid Size")
        self._size = value

#     def getSize(self):
#         return self.size

    def set_size(self, value):
        self.size = value
