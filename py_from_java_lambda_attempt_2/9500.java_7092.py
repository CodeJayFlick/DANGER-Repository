Here is the translation of the Java code into Python:

```Python
class GHtmlCheckBox(JCheckBox):
    def __init__(self):
        super().__init__()

    def __init__(self, icon: Icon):
        super(icon)

    def __init__(self, icon: Icon, selected: bool):
        super(icon, selected)

    def __init__(self, text: str):
        super(text)

    def __init__(self, action: Action):
        super(action)

    def __init__(self, text: str, selected: bool):
        super(text, selected)

    def __init__(self, text: str, icon: Icon):
        super(text, icon)

    def __init__(self, text: str, icon: Icon, selected: bool):
        super(text, icon, selected)
```

Note that Python does not have a direct equivalent to Java's `package` statement. Also, the `GComponent` interface is not present in this translation as it seems to be specific to GHIDRA and may require additional imports or implementation.

The above code assumes you are using the `JCheckBox` class from the `javax.swing` module.