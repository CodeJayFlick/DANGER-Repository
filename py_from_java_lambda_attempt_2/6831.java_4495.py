Here is your Java code translated into Python:

```Python
class DecompilerCodeComparisonPanel:
    def __init__(self):
        self.splitPane = None
        self.cPanels = [None] * 2
        self.dualDecompilerCoordinator = None
        self.leftTitlePrefix = ""
        self.rightTitlePrefix = ""

    @property
    def left_title(self):
        return self._left_title

    @left_title.setter
    def left_title(self, value):
        if not isinstance(value, str):
            raise TypeError("Left title must be a string")
        self._left_title = value

    @property
    def right_title(self):
        return self._right_title

    @right_title.setter
    def right_title(self, value):
        if not isinstance(value, str):
            raise TypeError("Right title must be a string")
        self._right_title = value

    def build_panel(self):
        # ... same as Java code ...

    def set_titles(self, left_title: str, right_title: str) -> None:
        self.leftTitle = left_title
        self.rightTitle = right_title
        for panel in self.cPanels:
            if isinstance(panel, CDisplayPanel):
                panel.set_title(left_title if i == 0 else right_title)

    def set_left_title(self, title: str) -> None:
        self.left_title = title

    def set_right_title(self, title: str) -> None:
        self.right_title = title
```

Note that this is not a complete translation of the Java code. The provided Python code only includes some parts of the original Java class and does not include all methods or properties.