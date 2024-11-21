Here is the equivalent Python code:

```Python
class IsAsciiColumnConstraint:
    def accepts(self, value: str, context=None) -> bool:
        if not isinstance(value, str):
            return False
        
        for char in value:
            if ord(char) >= 0x80:
                return False
        
        return True

    def get_name(self) -> str:
        return "Is Ascii"

# Note that Python does not have a direct equivalent to Java's DoNothingColumnConstraintEditor
```

Note: The `DoNothingColumnConstraintEditor` is used in the original code as an editor for this constraint. In Python, we don't need such an editor because it doesn't provide any functionality other than displaying itself.