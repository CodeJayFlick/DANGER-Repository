Here is the translation of the given Java code into equivalent Python:

```Python
from ghidra_framework_options_editor import EditorState
import layout as HorizontalLayout


class CustomOptionComponent:
    def __init__(self, editor_state):
        super().__init__(editor_state)

        # this layout allows us to easily left-align the single component in this container
        self.setLayout(HorizontalLayout(0))

        # this class is designed to let the editor component handle the display and editing
        self.add(editor_state.getEditorComponent())

    def getPreferredAlignmentSize(self):
        return (0, 0)
```

Please note that Python does not have direct equivalent of Java's `package`, `import java.awt.Dimension;` or `@Override`. Also, Python is an interpreted language which means it doesn't support some features like static methods and method overriding.