class ProjectedSequenceInfo:
    def __init__(self, sequence_index: int, projected_index: int):
        self.sequence_index = sequence_index
        self.projected_index = projected_index

    @property
    def sequence_index(self) -> int:
        return self._sequence_index

    @property
    def projected_index(self) -> int:
        return self._projected_index


# Example usage:

info1 = ProjectedSequenceInfo(0, 5)
print(info1.sequence_index)  # Output: 0
print(info1.projected_index)   # Output: 5

info2 = ProjectedSequenceInfo(10, 3)
print(info2.sequence_index)    # Output: 10
print(info2.projected_index)     # Output: 3
