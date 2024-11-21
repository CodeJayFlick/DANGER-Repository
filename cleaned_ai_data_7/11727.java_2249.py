import xml.etree.ElementTree as ET

class Pattern:
    def dispose(self):
        pass

    def simplify_clone(self):
        raise NotImplementedError("Must be implemented by subclass")

    def shift_instruction(self, sa: int):
        raise NotImplementedError("Must be implemented by subclass")

    def do_or(self, b: 'Pattern', sa: int) -> 'Pattern':
        raise NotImplementedError("Must be implemented by subclass")

    def do_and(self, b: 'Pattern', sa: int) -> 'Pattern':
        raise NotImplementedError("Must be implemented by subclass")

    def common_sub_pattern(self, b: 'Pattern', sa: int) -> 'Pattern':
        raise NotImplementedError("Must be implemented by subclass")

    def is_match(self, pos: object) -> bool:
        return False  # Default implementation

    def num_disjoint(self) -> int:
        raise NotImplementedError("Must be implemented by subclass")

    def get_disjoint(self, i: int) -> 'DisjointPattern':
        raise NotImplementedError("Must be implemented by subclass")

    def always_true(self) -> bool:
        return True  # Default implementation

    def always_false(self) -> bool:
        return False  # Default implementation

    def always_instruction_true(self) -> bool:
        return False  # Default implementation

    def save_xml(self, s: object):
        raise NotImplementedError("Must be implemented by subclass")

    def restore_xml(self, el: ET.Element):
        raise NotImplementedError("Must be implemented by subclass")
