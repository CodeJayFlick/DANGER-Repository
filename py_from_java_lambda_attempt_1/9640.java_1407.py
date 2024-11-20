Here is the translation of the Java code to Python:
```
class InvertedTextFilter:
    def __init__(self, filter):
        self.filter = filter

    def is_sub_filter_of(self, text_filter):
        # Inverted filters can't add back data that has already been filtered out
        return False

    def matches(self, text):
        return not self.filter.matches(text)

    def get_filter_text(self):
        return self.filter.get_filter_text()

    def __hash__(self):
        raise NotImplementedError("Not meant to put in hashing structures; the data for equals may change over time")

    def __eq__(self, obj):
        if self is obj:
            return True
        if obj is None:
            return False
        if not isinstance(obj, InvertedTextFilter):
            return False

        other = obj
        if not filter == other.filter:
            return False
        return True
```
Note that I've used the following Python concepts:

* Classes and objects (`class` keyword)
* Constructors (`__init__` method)
* Methods (e.g. `matches`, `get_filter_text`)
* Exception handling (`raise NotImplementedError`)
* Equality comparison (`==` operator) with custom implementation in `__eq__` method
* Inheritance (not used in this specific code, but implied by the use of `isinstance`)