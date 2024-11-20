Here is the translation of the given Java code into equivalent Python:

```Python
class InMemoryFunctionTag:
    def __init__(self, name: str, comment: str = None):
        self.name = name
        if comment is None:
            self.comment = ""
        else:
            self.comment = comment

    @property
    def id(self) -> int:
        return -1  # equivalent to long in Java

    @property
    def name(self) -> str:
        return self.name

    @property
    def comment(self) -> str:
        return self.comment

    def set_name(self, new_name: str):
        raise ValueError("Immutable tag")

    def set_comment(self, new_comment: str):
        raise ValueError("Immutable tag")

    def compare_to(self, other_tag: 'InMemoryFunctionTag') -> int:
        if self.name.lower() > other_tag.name.lower():
            return 1
        elif self.name.lower() < other_tag.name.lower():
            return -1
        else:
            if self.comment is None and other_tag.comment is not None:
                return -1
            elif self.comment is not None and other_tag.comment is None:
                return 1
            elif self.comment is None and other_tag.comment is None:
                return 0
            else:
                if self.comment.lower() > other_tag.comment.lower():
                    return 1
                elif self.comment.lower() < other_tag.comment.lower():
                    return -1
                else:
                    return 0

    def __hash__(self) -> int:
        prime = 31
        result = 1
        if self.comment is not None:
            result *= prime + hash(self.comment)
        if self.name is not None:
            result *= prime + hash(self.name)
        return result

    def __eq__(self, other):
        if isinstance(other, InMemoryFunctionTag):
            if self.name != other.name or self.comment != other.comment:
                return False
            else:
                return True
        elif other is None:
            return False
        else:
            return NotImplemented

    def delete(self) -> None:
        pass  # equivalent to void in Java, does nothing

    def __str__(self):
        if self.comment is not None and len(self.comment) > 0:
            return f"In-memory tag: {self.name} ({self.comment})"
        else:
            return f"In-memory tag: {self.name}"
```

Please note that Python's `@property` decorator does not have a direct equivalent in Java. It was used here to create getter methods for the attributes of this class, similar to how you would use getters and setters in Java.