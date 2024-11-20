class ReverseListIterator:
    def __init__(self, list_, root, node):
        self.list_ = list_
        self.root = root
        self.node = node
    
    def copy(self):
        return ReverseListIterator(self.list_, self.root, self.node)
    
    def is_begin(self):
        return self.node == self.root.prev
    
    def decrement(self):
        if self.node.prev == self.root:
            raise IndexError()
        self.node = self.node.next
        return self
    
    def increment(self):
        self.node = self.node.prev
        return self
    
    def insert(self, value):
        new_node = ListNodeSTL(value)
        new_node.next.prev = new_node
        new_node.next = new_node
        self.node = new_node
        self.list_.adjust_size(1)
    
    def __eq__(self, obj):
        if obj is None:
            return False
        if isinstance(obj, ReverseListIterator) and obj is not self:
            other = obj
            return self.list_ == other.list_ and self.node == other.node
    
    def __hash__(self):
        return hash(self.list_)
