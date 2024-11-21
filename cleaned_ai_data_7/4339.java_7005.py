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
