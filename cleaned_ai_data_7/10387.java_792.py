class FullKeySet:
    def __init__(self, num_keys):
        self.num_keys = num_keys

    def size(self):
        return self.num_keys

    def contains_key(self, key):
        if 0 <= key < self.num_keys:
            return True
        else:
            return False

    def get_first(self):
        return 0

    def get_last(self):
        return self.num_keys - 1

    def put(self, key):
        if not (0 <= key < self.num_keys):
            raise IndexError("Index out of bounds")

    def remove(self, key):
        if not (0 <= key < self.num_keys):
            raise IndexError("Index out of bounds")
        else:
            return False  # This method does nothing in the original Java code

    def remove_all(self):
        pass  # This method is supposed to do something but it doesn't in this implementation

    def get_next(self, key):
        if not (0 <= key < self.num_keys - 1):
            raise IndexError("Index out of bounds")
        elif key == self.num_keys - 1:
            return -1
        else:
            return key + 1

    def get_previous(self, key):
        if not (0 <= key < self.num_keys - 1):
            raise IndexError("Index out of bounds")
        elif key == 0:
            return -1
        else:
            return key - 1

    def is_empty(self):
        return False
