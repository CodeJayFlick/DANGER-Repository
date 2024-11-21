from typing import Set, FrozenSet

class SolverHint:
    @staticmethod
    def with(hints: set, *plus) -> frozenset:
        hints = set(hints)
        for hint in plus:
            hints.add(hint)
        return frozenset(hints)

# Example usage:

hints1 = {SolverHint()}  # Initialize a set of SolverHints
hints2 = SolverHint.with(hints1, *[])  # Add more hints to the existing ones

print(type(hints2))  # Output: <class 'frozenset'>
