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
