Here is the equivalent Python code:

```
class TsFileConstant:
    TSFILE_SUFFIX = ".tsfile"
    TSFILE_HOME = "TSFILE_HOME"
    TSFILE_CONF = "TSFILE_CONF"
    PATH_ROOT = "root"
    TMP_SUFFIX = "tmp"
    PATH_SEPARATOR = "."
    PATH_SEPARATOR_CHAR = "."
    PATH_SEPARATER_NO_REGEX = "\\."

    TIME_COLUMN_MASK = 0x80
    VALUE_COLUMN_MASK = 0x40

    def __init__(self):
        pass
```

Note that in Python, we don't need to use `public` or `static`, as these are implicit. Also, the equivalent of Java's `final` keyword is not needed in Python, as variables can be reassigned if desired.