Here is the translation of the Java code to Python:
```
class FcgEdge:
    def __init__(self, start: 'FcgVertex', end: 'FcgVertex'):
        super().__init__(start, end)

    def clone_edge(self, start: 'FcgVertex', end: 'FcgVertex') -> 'FcgEdge':
        return FcgEdge(start, end)

    def is_direct_edge(self) -> bool:
        start_level = self.start.get_level()
        end_level = self.end.get_level()

        if start_level.is_source() or end_level.is_source():
            # all info leaving the source is important/'direct'
            return True

        parent = start_level.parent
        if parent == end_level:
            return True

        child = start_level.child
        return child == end_level
```
Note that I used Python 3.6+ syntax and features, such as type hints (e.g., `-> 'FcgEdge'`) and the `super()` function with parentheses.

Also, since there is no direct equivalent to Java's `@SuppressWarnings` annotation in Python, I did not include any suppression of warnings or errors.