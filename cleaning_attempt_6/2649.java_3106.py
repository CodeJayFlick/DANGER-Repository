class WrappingInstructionIterator:
    def __init__(self, iterator):
        self.iterator = iterator

    def __iter__(self):
        return self

    def __next__(self):
        if not hasattr(self, 'it'):
            raise StopIteration
        try:
            result = next(self.it)
        except StopIteration:
            del self.it
            raise
        return result

    @property
    def has_next(self):
        return bool(self.iterator)

# Example usage:
class Instruction: pass  # placeholder for actual instruction class
def my_iterator():
    yield Instruction()
    yield Instruction()

it = WrappingInstructionIterator(my_iterator())
for inst in it:
    print(inst)
