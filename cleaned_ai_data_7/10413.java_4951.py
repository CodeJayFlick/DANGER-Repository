class ObjectArray:
    MIN_SIZE = 4

    def __init__(self):
        self.objs = [None] * self.MIN_SIZE
        self.last_non_zero_index = -1

    def __init__(self, size):
        if size < self.MIN_SIZE:
            size = self.MIN_SIZE
        self.objs = [None] * size
        self.last_non_zero_index = -1

    def put(self, index, value):
        if value is None:
            self.remove(index)
            return
        
        if index >= len(self.objs):
            self.adjust_array(max(index + 1, len(self.objs) * 2))
        
        self.objs[index] = value
        if index > self.last_non_zero_index:
            self.last_non_zero_index = index

    def remove(self, index):
        if index >= len(self.objs):
            return
        
        self.objs[index] = None
        if index == self.last_non_zero_index:
            self.last_non_zero_index = self.find_last_non_zero_index()
        
        if self.last_non_zero_index < len(self.objs) // 4:
            self.adjust_array(self.last_non_zero_index * 2)

    def find_last_non_zero_index(self):
        for i in range(self.last_non_zero_index, -1, -1):
            if self.objs[i] is not None:
                return i
        
        return -1

    def get(self, index):
        if index < len(self.objs):
            return self.objs[index]
        
        return None

    def adjust_array(self, size):
        if size < self.MIN_SIZE:
            size = self.MIN_SIZE
        new_objs = [None] * size
        length = min(size, len(self.objs))
        new_objs[:length] = self.objs[:length]
        self.objs = new_objs

    def get_last_non_empty_index(self):
        return self.last_non_zero_index


class DataTable:
    pass
