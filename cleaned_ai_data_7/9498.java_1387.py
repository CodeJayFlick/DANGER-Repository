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
