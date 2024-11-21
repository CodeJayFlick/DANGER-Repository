class InstructionSearchAddressIterator:
    def __init__(self, instruction_iterator):
        self.instruction_iterator = instruction_iterator

    def has_next(self):
        return self.instruction_iterator.has_next()

    def next(self):
        instruction = self.instruction_iterator.next()
        return instruction.get_address()

    def remove(self):
        raise UnsupportedOperationException("Remove operation not supported")

class UnsupportedOperationException(Exception):
    pass
