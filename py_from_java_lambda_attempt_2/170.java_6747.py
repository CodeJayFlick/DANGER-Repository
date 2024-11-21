Here is the translation of the Java code to Python:
```
class BranchPcodeRow:
    def __init__(self, sequence: int, from_seq: int):
        self.sequence = sequence
        self.from_seq = from_seq

    def get_sequence(self) -> int:
        return self.sequence

    def get_code(self) -> str:
        return f"(branched from {self.from_seq})"

    def get_op(self) -> None:
        return None
```
Note that I've used Python's type hints to indicate the types of the variables and method returns, but this is not strictly necessary for a working program.