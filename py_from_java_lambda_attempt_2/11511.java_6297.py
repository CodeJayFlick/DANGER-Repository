Here is the translation of the Java code into Python:

```Python
class Pattern:
    def simplify_clone(self):
        pass  # Abstract method implementation left out for simplicity

    def shift_instruction(self, sa: int) -> None:
        pass  # Abstract method implementation left out for simplicity

    def do_or(self, b: 'Pattern', sa: int) -> 'Pattern':
        pass  # Abstract method implementation left out for simplicity

    def do_and(self, b: 'Pattern', sa: int) -> 'Pattern':
        pass  # Abstract method implementation left out for simplicity

    def is_match(self, walker: object, debug: object) -> bool:
        return False  # Default value of boolean type

    def num_disjoint(self) -> int:
        return 0  # Default value of integer type

    def get_disjoint(self, i: int) -> 'DisjointPattern':
        pass  # Abstract method implementation left out for simplicity

    def always_true(self) -> bool:
        return False  # Default value of boolean type

    def always_false(self) -> bool:
        return True  # Default value of boolean type

    def always_instruction_true(self) -> bool:
        return False  # Default value of boolean type

    def restore_xml(self, parser: object) -> None:
        pass  # Abstract method implementation left out for simplicity
```

Note that Python does not support abstract classes and methods like Java. The `simplify_clone`, `shift_instruction`, `do_or`, `do_and`, `get_disjoint` are just placeholders as they were in the original code, but their actual implementations would depend on your specific use case.