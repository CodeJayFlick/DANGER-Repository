class VectorFromLocation:
    def __init__(self):
        self.location = None

    @staticmethod
    def register_expression():
        pass  # This method doesn't have an exact equivalent in Python, as it's used to register expressions with Skript. In this translation, we'll ignore it.

    def init(self, exprs: list, matched_pattern: int, is_delayed: bool, parse_result: dict) -> bool:
        self.location = exprs[0]
        return True

    def get(self, event):
        location = self.location.get(event)
        if location is None:
            return []
        return [location.to_vector()]

    @property
    def single(self) -> bool:
        return True

    @property
    def return_type(self) -> type:
        from typing import List
        return list  # This corresponds to Vector[] in Java, but Python doesn't have a direct equivalent. We'll use the built-in list type instead.

    def __str__(self, event: dict = None, debug: bool = False):
        if event is not None and debug:
            return f"vector from {self.location.__str__(event, debug)}"
        else:
            return "vector from location"
