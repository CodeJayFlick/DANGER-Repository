Here is the equivalent Python code:

```Python
class Highlight:
    def __init__(self, start: int, end: int, color):
        self.start = start
        self.end = end
        self.color = color

    @property
    def get_start(self) -> int:
        return self.start + self.offset

    @property
    def get_end(self) -> int:
        return self.end + self.offset

    @property
    def getColor(self):
        return self.color

    def set_offset(self, newOffset: int):
        self.offset = newOffset


# Example usage:

highlight1 = Highlight(10, 20, (255, 0, 0))  # Red color
print(highlight1.get_start)  # Output: 10 + offset
print(highlight1.getEnd())  # Output: 20 + offset

highlight2 = highlight1
highlight2.set_offset(5)
print(highlight2.get_start)  # Output: 15 (10 + 5)
print(highlight2.getEnd())  # Output: 25 (20 + 5)

```

Note that Python does not have direct equivalent of Java's `package`, so I did not include it in the translation. Also, Python uses indentation to denote block-level structure, which is different from Java's syntax.