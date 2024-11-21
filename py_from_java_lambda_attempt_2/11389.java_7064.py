Here is the translation of the given Java code into equivalent Python:

```Python
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
```

Note that Python does not have direct equivalents for Java's `Set` and `HashSet`, but we can use a set in Python. The equivalent of Java's `Collections.unmodifiableSet()` is achieved by converting the mutable set to an immutable frozenset using the `frozenset()` function.

The example usage at the end demonstrates how you would create sets of SolverHints, add more hints to existing ones and convert them into unchangeable frozensets.