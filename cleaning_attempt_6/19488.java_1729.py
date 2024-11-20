class AlphabeticalSort:
    def __init__(self):
        pass

    @staticmethod
    def register_expression():
        Skript.register_expression(AlphabeticalSort)

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        self.texts = exprs[0]
        return True

    def get(self, e):
        sorted_texts = self.texts.get_all(e).copy()  # Not yet sorted
        sorted_texts.sort()
        return [str(x) for x in sorted_texts]

    @property
    def return_type(self):
        return str

    def is_single(self):
        return False

    def __str__(self, e=None, debug=False):
        if not e:
            return "alphabetically sorted strings: " + self.texts.__str__()
        else:
            return f"alphabetically sorted strings at event {e}: " + self.texts.__str__()

# Usage
AlphabeticalSort.register_expression()
