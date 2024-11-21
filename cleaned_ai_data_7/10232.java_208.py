class MultiMapSTL:
    def __init__(self):
        self.rb_tree = {}

    def add(self, key, value):
        if not isinstance(key, tuple) or len(key) > 1:
            raise ValueError("Key must be an iterable with one element")
        if key in self.rb_tree:
            self.rb_tree[key].append(value)
        else:
            self.rb_tree[key] = [value]

    def contains(self, key):
        return key in self.rb_tree

    def remove(self, key):
        if not isinstance(key, tuple) or len(key) > 1:
            raise ValueError("Key must be an iterable with one element")
        if key in self.rb_tree:
            value = self.rb_tree.pop(key)
            return value
        else:
            return None

    def erase(self, iter):
        for node in list(iter):
            if not isinstance(node[0], tuple) or len(node[0]) > 1:
                raise ValueError("Key must be an iterable with one element")
            self.rb_tree.pop(node[0])

    def begin(self):
        return [(k, v) for k, vs in sorted(self.rb_tree.items()) for v in vs]

    def end(self):
        return []

    def rBegin(self):
        return list(reversed(list(self.begin())))

    def rEnd(self):
        return []

    def lower_bound(self, key):
        if not isinstance(key, tuple) or len(key) > 1:
            raise ValueError("Key must be an iterable with one element")
        for k in sorted(self.rb_tree.keys()):
            if k >= key:
                yield from self rb_tree[k]
            else:
                break

    def upper_bound(self, key):
        if not isinstance(key, tuple) or len(key) > 1:
            raise ValueError("Key must be an iterable with one element")
        for k in sorted(self.rb_tree.keys()):
            if k >= key:
                yield from self rb_tree[k]
            else:
                break

    def main(self):
        set = MultiMapSTL()
        set.add((7, "dog"))
        set.add((3, "blue"))
        set.add((9, "elf"))
        set.add((20,"gate"))
        set.add((15, "fog"))
        set.add((1, "apple"))
        set.add((20, "hog"))
        set.add((20,"indian"))
        set.add((4, "cat"))
        set.add((50, "jump"))

#       it = set.begin()
#       while not it.end():
#           print("value =", next(it))
#
#       print("---")
#       it = set.rBegin()
#       while not it.end():
#           print("value =", next(it))

if __name__ == "__main__":
    MultiMapSTL().main()

