class AbstractPatternTextFilter:
    def __init__(self, filter_text):
        self.filter_text = filter_text
        self.filter_pattern = None

    def create_pattern(self):
        # This method should be implemented by subclasses.
        pass

    def matches(self, text: str) -> bool:
        if not text:
            return False

        pattern = self.get_filter_pattern()
        if not pattern:
            return False

        return self.matches(text, pattern)

    def get_filter_text(self):
        return self.filter_text

    def get_filter_pattern(self):
        if not self.filter_pattern:
            self.filter_pattern = self.create_pattern()
        return self.filter_pattern

    def matches(self, text: str, pattern) -> bool:
        # This method should be implemented by subclasses.
        pass

    def __hash__(self):
        raise NotImplementedError("Not meant to put in hashing structures; the data for equals may change over time")

    def __eq__(self, other):
        if self is other:
            return True
        if not isinstance(other, AbstractPatternTextFilter):
            return False

        pattern_equal = self.patterns_equal(self.create_pattern(), other.create_pattern())
        filter_text_equal = self.filter_text == other.filter_text
        return pattern_equal and filter_text_equal

    def patterns_equal(self, p1: Pattern, p2: Pattern) -> bool:
        if not p1 or not p2:
            return False

        my_pattern = str(p1)
        other_pattern = str(p2)

        if my_pattern != other_pattern:
            return False

        f1 = p1.flags()
        f2 = p2.flags()

        return f1 == f2

    def __str__(self):
        return "{\n" + \
               "\tfilter: " + self.filter_text + ",\n" + \
               "\tpattern: " + str(self.get_filter_pattern()) + ",\n" + \
               "}"
