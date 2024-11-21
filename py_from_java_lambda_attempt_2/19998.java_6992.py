Here is the translation of the Java code to Python:

```Python
class ReversedListView(list):
    def __init__(self, list):
        self.list = list

    def size(self):
        return len(self.list)

    def empty(self):
        return not bool(self.list)

    def contains(self, o):
        return o in self.list

    def iterator(self):
        for i in range(len(self.list) - 1, -1, -1):
            yield self.list[i]

    def list_iterator(self):
        return self.iterator()

    def list_iterator(self, index):
        if index < len(self.list) and index >= 0:
            return self.list_iterator()
        else:
            raise IndexError

    def to_list(self):
        return [x for x in self]

    def add(self, e):
        self.list.insert(0, e)
        return True

    def remove(self, o):
        try:
            i = len(self.list) - 1 - list.index(o)
            del self.list[i]
            return True
        except ValueError:
            return False

    def contains_all(self, c):
        for x in c:
            if not self.contains(x):
                return False
        return True

    def add_all(self, c):
        for e in c:
            self.add(e)
        return True

    def add_all(self, index, c):
        i = len(self.list) - 1 - index
        for e in c:
            self.insert(i, e)
        return True

    def remove_all(self, c):
        while any(x in c for x in self):
            try:
                i = len(self.list) - 1 - list.index(next(x for x in c if x in self))
                del self.list[i]
            except ValueError:
                pass
        return True

    def retain_all(self, c):
        self[:] = [x for x in self if x in c]
        return True

    def clear(self):
        self.clear()

    def get(self, index):
        try:
            i = len(self.list) - 1 - index
            return self.list[i]
        except IndexError:
            raise IndexError("Index out of range")

    def set(self, index, e):
        try:
            i = len(self.list) - 1 - index
            self.insert(i, e)
            return True
        except IndexError:
            raise IndexError("Index out of range")

    def add_at_index(self, index, e):
        if index < len(self.list) and index >= 0:
            self.insert(index, e)
            return True
        else:
            raise IndexError

    def remove_at_index(self, index):
        try:
            i = len(self.list) - 1 - index
            del self.list[i]
            return True
        except IndexError:
            raise IndexError("Index out of range")

    def index_of(self, o):
        for i in range(len(self.list)):
            if self.list[-i-1] == o:
                return len(self.list) - i - 2

    def last_index_of(self, o):
        try:
            i = list.index(o)
            return len(self.list) - i - 2
        except ValueError:
            return None

    def sub_list(self, fromIndex, toIndex):
        if fromIndex < 0 or toIndex > len(self.list):
            raise IndexError("Index out of range")
        l = self[list(range(len(self.list)-toIndex-1, len(self.list)-fromIndex))][::-1]
        return ReversedListView(l)

    def __hash__(self):
        hash_code = 1
        for e in self:
            if not isinstance(e, type(None)):
                hash_code *= 31 + e.__hash__()
        return hash_code

    def __eq__(self, other):
        if id(self) == id(other):
            return True
        elif not isinstance(other, list):
            return False
        else:
            for i in range(len(self)-1, -1, -1):
                try:
                    j = len(other) - 1 - self.index(other[-i-1])
                    if self[i] != other[j]:
                        return False
                except ValueError:
                    pass
            return True

    def __repr__(self):
        return str(self)
```

This Python code is a direct translation of the Java code provided.