class MultiSetSTL:
    def __init__(self):
        self.rb_tree = {}

    def insert(self, key):
        if not isinstance(key, tuple) or len(key) != 2:
            raise ValueError("Key must be a pair")
        self.rb_tree[key] = key

    def contains(self, key):
        return key in self.rb_tree

    def remove(self, key):
        return key in self.rb_tree and del self.rb_tree[key]

    class SetIterator:
        def __init__(self, rb_tree, node=None):
            self.rb_tree = rb_tree
            self.node = node

        def __iter__(self):
            if not hasattr(self, 'node'):
                raise StopIteration
            return self

        def __next__(self):
            if self.node is None:
                raise StopIteration
            value = self.node[0]
            self.node = self.rb_tree.get(value)
            return value


class RedBlackTree:
    def __init__(self, comparator=None, ordered=False):
        self.comparator = comparator or lambda x: x
        self.ordered = ordered

    def put(self, key, value):
        if not isinstance(key, tuple) or len(key) != 2:
            raise ValueError("Key must be a pair")
        return (key, None)

    def contains_key(self, key):
        return key in self.rb_tree


class MultiSetSTLTest:
    def test_insert_remove_contain(self):
        set = MultiSetSTL()
        set.insert((7,))
        set.insert((3,))
        set.insert((9,))
        set.insert((20,))
        set.insert((15,))
        set.insert((1,))
        set.insert((4,))
        set.insert((50,))

    def test_begin_end_rBegin(self):
        set = MultiSetSTL()
        it = set.SetIterator(set.rb_tree)
        while not it.node is None:
            print("value =", it.next())
        print("---")
        it = set.SetIterator(set.rb_tree, None)
        while not it.node is None:
            print("value =", it.next())

    def test_lower_bound(self):
        set = MultiSetSTL()
        it = set.SetIterator(set(rb_tree), (20,))
        while not it.isEnd():
            print("value =", it.getAndIncrement())
