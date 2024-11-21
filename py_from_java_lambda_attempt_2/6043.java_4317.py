Here is the translation of the given Java code into Python:

```Python
import unittest

class Address:
    def __init__(self, space, offset):
        self.space = space
        self.offset = offset

    def get_address(self):
        return f"{self.space}+0x{self.offset:x}"

class NumberAddressIterator:
    def __init__(self, values):
        self.values = values
        self.current = 0

    def has_next(self):
        return self.current < len(self.values)

    def next(self):
        if not self.has_next():
            raise StopIteration
        address = Address("Bob", self.values[self.current])
        self.current += 1
        return address.get_address()

class MultiAddressIterator:
    def __init__(self, iterators, forward=True):
        self.iterators = iterators
        self.forward = forward

    def has_next(self):
        for iterator in self.iterators:
            if iterator.has_next():
                return True
        return False

    def next(self):
        for iterator in self.iterators:
            if iterator.has_next():
                address = iterator.next()
                return address
        raise StopIteration

class ExactSearchAddressIteratorTest(unittest.TestCase):

    def setUp(self):
        self.space = "Bob"
        self.addresses = []

    def test_single_iterator_forward(self):
        search_iterators = [NumberAddressIterator([1, 2, 3])]
        exact_search_iterator = MultiAddressIterator(search_iterators)
        while exact_search_iterator.has_next():
            address = exact_search_iterator.next()
            print(address)
        self.assertFalse(exact_search_iterator.has_next())

    def test_single_iterator_backward(self):
        search_iterators = [NumberAddressIterator([3, 2, 1])]
        exact_search_iterator = MultiAddressIterator(search_iterators, forward=False)
        while exact_search_iterator.has_next():
            address = exact_search_iterator.next()
            print(address)
        self.assertFalse(exact_search_iterator.has_next())

    def test_multiple_iterators_forward(self):
        search_iterators = [NumberAddressIterator([1, 5, 7]), NumberAddressIterator([2, 4, 6, 8, 10])]
        exact_search_iterator = MultiAddressIterator(search_iterators)
        while exact_search_iterator.has_next():
            address = exact_search_iterator.next()
            print(address)
        self.assertFalse(exact_search_iterator.has_next())

    def test_multiple_iterators_backward(self):
        search_iterators = [NumberAddressIterator([0x64, 0x61, 0x32]), NumberAddressIterator([0x3e8, 0x384, 0x21, 0xb, 1])]
        exact_search_iterator = MultiAddressIterator(search_iterators, forward=False)
        while exact_search_iterator.has_next():
            address = exact_search_iterator.next()
            print(address)
        self.assertFalse(exact_search_iterator.has_next())

    def test_multiple_iterators_duplicate_addresses(self):
        search_iterators = [NumberAddressIterator([1, 5, 7]), NumberAddressIterator([2, 4, 5, 7, 10])]
        exact_search_iterator = MultiAddressIterator(search_iterators)
        while exact_search_iterator.has_next():
            address = exact_search_iterator.next()
            print(address)
        self.assertFalse(exact_search_iterator.has_next())

    def test_single_iterator_has_next_many_times_forward(self):
        search_iterators = [NumberAddressIterator([1, 2, 3])]
        exact_search_iterator = MultiAddressIterator(search_iterators)
        for _ in range(4):
            address = exact_search_iterator.next()
            print(address)
        self.assertFalse(exact_search_iterator.has_next())

    def test_single_iterator_has_next_many_times_backward(self):
        search_iterators = [NumberAddressIterator([3, 2, 1])]
        exact_search_iterator = MultiAddressIterator(search_iterators, forward=False)
        for _ in range(4):
            address = exact_search_iterator.next()
            print(address)
        self.assertFalse(exact_search_iterator.has_next())

    def test_next_many_times_without_calling_has_next_forward(self):
        search_iterators = [NumberAddressIterator([1, 2, 3])]
        exact_search_iterator = MultiAddressIterator(search_iterators)
        for _ in range(3):
            address = exact_search_iterator.next()
            print(address)
        self.assertFalse(exact_search_iterator.has_next())

    def test_next_many_times_without_calling_has_next_backward(self):
        search_iterators = [NumberAddressIterator([3, 2, 1])]
        exact_search_iterator = MultiAddressIterator(search_iterators, forward=False)
        for _ in range(3):
            address = exact_search_iterator.next()
            print(address)
        self.assertFalse(exact_search_iterator.has_next())

if __name__ == '__main__':
    unittest.main()
```

Please note that Python does not have direct equivalent of Java's `Address` and `MultiAddressIterator`. The above code is a translation of the given Java code into Python.