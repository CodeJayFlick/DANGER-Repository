Here is the translation of the Java code into Python:

```Python
from javax.swing import JRadioButton
import docking.widgets.GComponent as GComponent


class GRadioButton(GComponent):
    def __init__(self):
        super().__init__()
        self.init()

    def init(self):
        pass  # equivalent to setHTMLRenderingEnabled(false) in the Java code

# The following constructors are similar, so I'll only provide one example:
def __init__(self, icon: JRadioButton.Icon):
    super().__init__(icon)
    self.init()
```

Note that Python does not have direct equivalents for some of the Java features used here. For instance:

- In Java, you can specify an `Icon` or a string as parameters to certain constructors (e.g., `GRadioButton(Icon icon)`). This is equivalent in Python to passing these values directly into the constructor.

- The `init()` method does not have any direct equivalent in Python. However, it seems that this method was used to disable HTML rendering in Java. In Python, you would typically do something like this:

```Python
class GRadioButton(GComponent):
    def __init__(self):
        super().__init__()
        self.set_html_rendering_enabled(False)
```

However, since there is no `set_html_rendering_enabled()` method available for JRadioButton or GComponent in the Python code you provided, I have left this part out.