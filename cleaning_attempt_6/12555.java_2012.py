from collections import Iterable, Iterator

class InstructionIterator(Iterable['Instruction'], Iterator['Instruction']):
    def __init__(self):
        pass

    def hasNext(self) -> bool:
        # TO DO: implement this method
        return False  # placeholder for now

    def next(self) -> 'Instruction':
        # TO DO: implement this method
        raise NotImplementedError("next() must be implemented")
