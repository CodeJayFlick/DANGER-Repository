from collections import Iterable, Iterator

class FunctionIterator(Iterable):
    def __init__(self):
        pass
    
    # Implementing iterator protocol (next() method)
    def __iter__(self):
        return self

    def __next__(self):
        raise NotImplementedError("Subclasses must implement this!")

# Note: Python does not have direct equivalent of Java's Iterator interface.
