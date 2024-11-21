class QueueStub:
    def __init__(self):
        pass

    def size(self):
        return 0

    def isEmpty(self):
        return True

    def contains(self, o):
        return False

    def iterator(self):
        from collections import emptyiterator
        return emptyiterator()

    def to_list(self):
        return []

    def remove(self, o):
        return False

    def contains_all(self, c):
        return False

    def add_all(self, c):
        return False

    def remove_all(self, c):
        return False

    def retain_all(self, c):
        return False

    def clear(self):
        pass

    def add(self, e):
        return False

    def offer(self, e):
        return False

    def remove(self):
        return None

    def poll(self):
        return None

    def element(self):
        return None

    def peek(self):
        return None
