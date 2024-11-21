class MapSTL:
    def __init__(self):
        self.rb_tree = RedBlackTree()

    def put(self, key, value):
        self.rb_tree.put(key, value)

    def add(self, key, value):
        if self(rb_tree).contains_key(key):
            return False
        self.rb_tree.put(key, value)
        return True

    def contains(self, key):
        return self.rb_tree.contains_key(key)

    def remove(self, key):
        return self.rb_tree.remove(key)

    def begin(self):
        return MapIteratorSTL(self.rb_tree, self.rb_tree.first())

    def end(self):
        return MapIteratorSTL(self(rb_tree), None)

    def rBegin(self):
        return ReverseMapIteratorSTL(self(rb_tree), self(rb_tree.last()))

    def rEnd(self):
        return ReverseMapIteratorSTL(self(rb_tree), None)

    def erase(self, key):
        return remove(key)

    def empty(self):
        return self.rb_tree.is_empty()

    def lower_bound(self, key):
        node = self.rb_tree.lower_bound(key)
        return MapIteratorSTL(self.rb_tree, node)

    def upper_bound(self, key):
        node = self(rb_tree).upper_bound(key)
        it = MapIteratorSTL(self(rb_tree), node)
        return it

    def clear(self):
        self.rb_tree.remove_all()

    def erase(self, iter):
        if not isinstance(iter, MapIteratorSTL):
            raise ValueError("Invalid iterator")
        node = iter.node
        if node is None:
            raise IndexError()
        iter.node = node.get_successor()
        it.erased = True
        self(rb_tree).delete_entry(node)

    def erase(self, start, end):
        while not start.equals(end):
            erase(start)
            start.increment()

    def get(self, key):
        node = self.rb_tree.find_first_node(key)
        if node is None:
            return None
        return node.value

    def find(self, key):
        if self(rb_tree).contains_key(key):
            return lower_bound(key)
        return end()

    def size(self):
        return self.rb_tree.size()

    def insert(self, start, end):
        while not start.equals(end):
            add(start.get().first, start.get().second)
            start.increment()
