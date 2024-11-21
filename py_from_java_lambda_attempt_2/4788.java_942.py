Here is the translation of the Java code into Python:

```Python
class SegmentNames:
    PAGEZERO = "__PAGEZERO"
    TEXT = "__TEXT"
    DATA = "__DATA"
    OBJC = "__OBJC"
    ICON = "__ICON"
    LINKEDIT = "__LINKEDIT"
    UNIXSTACK = "__UNIXSTACK"
    IMPORT = "__IMPORT"

    TEXT_EXEC = "__TEXT_EXEC"
    PRELINK_TEXT = "__PRELINK_TEXT"


# Example usage:
print(SegmentNames.PAGEZERO)
```

Please note that Python does not have direct equivalent of Java's `public final static` keyword. In Python, you can achieve similar functionality using class variables and constants.