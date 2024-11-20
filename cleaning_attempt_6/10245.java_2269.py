class UnmodifiableListIterator:
    def __init__(self, iterator):
        self.iterator = iterator

    def assign(self, other_iterator):
        raise Exception("Cannot modify this iterator!")

    def decrement(self):
        raise Exception("Cannot modify this iterator!")

    def decrement_by_n(self, n):
        raise Exception("Cannot modify this iterator!")

    def delete(self):
        raise Exception("Cannot modify this iterator!")

    def delete_by_count(self, count):
        raise Exception("Cannot modify this iterator!")

    def increment(self):
        raise Exception("Cannot modify this iterator!")

    def increment_by_n(self, n):
        raise Exception("Cannot modify this iterator!")

    def insert_value(self, value):
        raise Exception("Cannot modify this iterator!")

    def set_value(self, value):
        raise Exception("Cannot modify this iterator!")
