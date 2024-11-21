import re

class FindsPatternTextFilter:
    def __init__(self, filter_text):
        self.filter_text = filter_text

    def create_pattern(self):
        try:
            pattern = re.compile(self.filter_text, re.DOTALL)
            return pattern
        except Exception as e:
            # This can happen as the user is typing their regex; not sure what else we can do.
            # The net effect is that the filter will appear to do nothing.
            return None

    def matches(self, text, pattern):
        if pattern.search(text):
            return True
        return False

    def is_sub_filter_of(self, parent_filter):
        if isinstance(parent_filter, FindsPatternTextFilter) and self.filter_text.startswith(parent_filter.filter_text):
            # only allow simple globbing characters (in order to avoid complex things like look ahead and look behind)
            for char in self.filter_text[parent_filter.filter_text.length():]:
                if not ((char >= 0x20 and char <= 0x5A) or
                       (char >= 0x5F and char <= 0x7A)):
                    return False
            return True
        return False

# Example usage:
filter = FindsPatternTextFilter("hello")
print(filter.create_pattern())
