class Node:
    def __init__(self):
        self.previous = None
        self.value = 0
        self.succeeding = None

    def remove(self):
        if self.previous:
            self.previous.succeeding = self.succeeding
        if self.succeeding:
            self.succeeding.previous = self.previous
        return self


class Cache:
    def __init__(self, capacity):
        self.head = Node()
        self.tail = Node()
        self.head.succeeding = self.tail
        self.tail.previous = self.head

        self.cached_nodes = [Node() for _ in range(capacity)]
        self.cache_capacity = capacity
        self.cache_size = 0

    def remove_first_occurrence(self, value):
        node = self.head.succeeding
        while node != self.tail:
            if node.value == value:
                cached_node = self.cached_nodes[self.cache_size - 1]
                cached_node.remove()
                self.cache_size -= 1
                return True
            node = node.succeeding
        return False

    def remove_last(self):
        last_node = self.tail.previous
        last_node.remove()
        self.cached_nodes[self.cache_size - 1] = last_node
        self.cache_size -= 1
        return last_node.value

    def add_first(self, value):
        node = Node()
        node.set(self.head, value, self.head.succeeding)
        self.cached_nodes[self.cache_size].set(self.head, value, self.head.succeeding)
        self.cache_size += 1


def clear(self):
    while self.cache_size != 0:
        self.remove_last()

